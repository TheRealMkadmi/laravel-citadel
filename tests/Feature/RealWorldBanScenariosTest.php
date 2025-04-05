<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Citadel;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\BanType;
use TheRealMkadmi\Citadel\Tests\TestCase;

class RealWorldBanScenariosTest extends TestCase
{
    private const TEST_API_ENDPOINT = '/api/test-endpoint';

    private const TEST_FRONTEND_ENDPOINT = '/frontend-endpoint';

    private const TEST_IP = '192.168.100.123';

    private const TEST_FINGERPRINT = 'test-ban-scenario-fingerprint';

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure middleware is enabled
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED, true);

        // Configure middleware to auto-ban when threshold is exceeded
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 50.0);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_BAN_DURATION, 60); // 1 minute ban

        // Define test routes with different middleware configurations
        $this->defineTestRoutes();
    }

    protected function defineTestRoutes(): void
    {
        // API endpoint protected with full middleware stack
        Route::middleware(['citadel-protect'])
            ->post(self::TEST_API_ENDPOINT, function (Request $request) {
                return response()->json([
                    'success' => true,
                    'message' => 'API endpoint accessed',
                    'fingerprint' => $request->getFingerprint(),
                    'ip' => $request->ip(),
                ]);
            });

        // Frontend endpoint with just ban checking
        Route::middleware(['citadel-ban'])
            ->get(self::TEST_FRONTEND_ENDPOINT, function (Request $request) {
                return response()->json([
                    'success' => true,
                    'message' => 'Frontend endpoint accessed',
                    'fingerprint' => $request->getFingerprint(),
                    'ip' => $request->ip(),
                ]);
            });
    }

    #[Test]
    public function banned_ip_is_consistently_blocked_across_routes()
    {
        // Get Citadel service
        $citadel = $this->app->make(Citadel::class);

        // Ban the IP
        $banResult = $citadel->banIp(self::TEST_IP, 60, 'Testing IP ban');
        $this->assertTrue($banResult, 'IP should be banned successfully');

        // Try to access the API endpoint with banned IP
        $apiResponse = $this->postJson(
            self::TEST_API_ENDPOINT,
            ['data' => 'test'],
            [],
            ['REMOTE_ADDR' => self::TEST_IP]
        );
        $apiResponse->assertStatus(403);

        // Try to access the frontend endpoint with the same banned IP
        $frontendResponse = $this->getJson(
            self::TEST_FRONTEND_ENDPOINT,
            [],
            ['REMOTE_ADDR' => self::TEST_IP]
        );
        $frontendResponse->assertStatus(403);

        // Unban the IP
        $unbanResult = $citadel->unban(self::TEST_IP, BanType::IP);
        $this->assertTrue($unbanResult, 'IP should be unbanned successfully');

        // Access should be restored
        $apiResponseAfterUnban = $this->postJson(
            self::TEST_API_ENDPOINT,
            ['data' => 'test'],
            [],
            ['REMOTE_ADDR' => self::TEST_IP]
        );
        $apiResponseAfterUnban->assertStatus(200);
    }

    #[Test]
    public function banned_fingerprint_is_blocked_regardless_of_ip()
    {
        // Get Citadel service
        $citadel = $this->app->make(Citadel::class);

        // Ban the fingerprint
        $banResult = $citadel->banFingerprint(self::TEST_FINGERPRINT, 60, 'Testing fingerprint ban');
        $this->assertTrue($banResult, 'Fingerprint should be banned successfully');

        // Try to access from different IPs but same fingerprint
        $ip1 = '192.168.1.1';
        $ip2 = '192.168.1.2';

        // First IP
        $response1 = $this->postJson(
            self::TEST_API_ENDPOINT,
            ['data' => 'test'],
            ['X-Fingerprint' => self::TEST_FINGERPRINT],
            ['REMOTE_ADDR' => $ip1]
        );
        $response1->assertStatus(403);

        // Different IP, same fingerprint
        $response2 = $this->postJson(
            self::TEST_API_ENDPOINT,
            ['data' => 'test'],
            ['X-Fingerprint' => self::TEST_FINGERPRINT],
            ['REMOTE_ADDR' => $ip2]
        );
        $response2->assertStatus(403);

        // Different IP, different fingerprint - should be allowed
        $response3 = $this->postJson(
            self::TEST_API_ENDPOINT,
            ['data' => 'test'],
            ['X-Fingerprint' => 'different-fingerprint'],
            ['REMOTE_ADDR' => $ip1]
        );
        $response3->assertStatus(200);
    }

    #[Test]
    public function automatic_ban_triggers_when_threshold_exceeded()
    {
        // Configure analyzers to provide a high score
        Config::set(CitadelConfig::KEY_BURSTINESS.'.enable_burstiness_analyzer', true);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 60.0);  // Above threshold
        Config::set(CitadelConfig::KEY_BURSTINESS.'.max_requests_per_window', 3); // Low threshold for easy triggering

        // Get DataStore for verification
        $dataStore = $this->app->make(DataStore::class);

        // First make several requests in succession to trigger burstiness detection
        $testFingerprint = 'auto-ban-test-fingerprint';

        // These requests will be counted but not blocked yet
        for ($i = 0; $i < 3; $i++) {
            $this->postJson(
                self::TEST_API_ENDPOINT,
                ['data' => "request_$i"],
                ['X-Fingerprint' => $testFingerprint]
            );
        }

        // This request should trigger the ban because it exceeds the threshold
        $finalResponse = $this->postJson(
            self::TEST_API_ENDPOINT,
            ['data' => 'final_request'],
            ['X-Fingerprint' => $testFingerprint]
        );

        // It should be blocked with a 403
        $finalResponse->assertStatus(403);

        // Verify the fingerprint is now banned in the system
        $citadel = $this->app->make(Citadel::class);
        $this->assertTrue(
            $citadel->isBanned($testFingerprint, BanType::FINGERPRINT),
            'Fingerprint should be automatically banned after exceeding threshold'
        );

        // Verify ban details
        $banDetails = $citadel->getBan($testFingerprint, BanType::FINGERPRINT);
        $this->assertNotNull($banDetails);
        $this->assertArrayHasKey('reason', $banDetails);
        $this->assertStringContainsString('Automatic ban', $banDetails['reason']);
    }
}
