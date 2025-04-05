<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class EndToEndFlowTest extends TestCase
{
    private const TEST_ENDPOINT = '/api/test-protected-endpoint';

    private const TEST_FINGERPRINT = 'test-end-to-end-fingerprint';

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure middleware is enabled
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true);

        // Configure reasonable thresholds for testing
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 50.0);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 20.0);

        // Enable analyzers but with moderate settings
        Config::set(CitadelConfig::KEY_BURSTINESS.'.enable_burstiness_analyzer', true);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 15.0);  // Below blocking, above warning

        // Set up test routes with various middleware configurations
        $this->defineEndToEndTestRoutes();
    }

    /**
     * Define test routes with Citadel protection for end-to-end testing
     */
    private function defineEndToEndTestRoutes(): void
    {
        Route::middleware(['citadel-protect'])
            ->post(self::TEST_ENDPOINT, function (Request $request) {
                return response()->json([
                    'success' => true,
                    'message' => 'Protected endpoint accessed',
                    'fingerprint' => $request->getFingerprint(),
                    'data' => $request->all(),
                ]);
            });
    }

    #[Test]
    public function complete_request_flow_with_fingerprint_extraction_and_analysis()
    {
        // First access - should get a warning but be allowed
        $response1 = $this->postJson(
            self::TEST_ENDPOINT,
            ['test_data' => 'value'],
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );

        // Should be allowed with warning headers
        $response1->assertStatus(200);
        $response1->assertHeader('X-Threat-Detected');
        $this->assertEquals(self::TEST_FINGERPRINT, $response1->json('fingerprint'));

        // Verify a score was recorded in the datastore
        $dataStore = $this->app->make(DataStore::class);
        $scoreKey = 'citadel:request_score:'.self::TEST_FINGERPRINT;
        $this->assertNotNull($dataStore->getValue($scoreKey), 'Request score should be recorded');

        // Simulate rapid succession of requests to trigger burstiness detection
        for ($i = 0; $i < 3; $i++) {
            $this->postJson(
                self::TEST_ENDPOINT,
                ['test_data' => "rapid_request_$i"],
                ['X-Fingerprint' => self::TEST_FINGERPRINT]
            );
        }

        // The final request should still be allowed but with increasing warnings
        $finalResponse = $this->postJson(
            self::TEST_ENDPOINT,
            ['test_data' => 'final_request'],
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );

        $finalResponse->assertStatus(200);
        $finalResponse->assertHeader('X-Threat-Detected');

        // Verify the score was increased due to burstiness
        $finalScore = $dataStore->getValue($scoreKey);
        $this->assertGreaterThan(0, $finalScore, 'Score should be greater than zero after multiple requests');
    }

    #[Test]
    public function different_fingerprints_are_analyzed_independently()
    {
        // First fingerprint with normal access
        $firstFingerprint = 'first-test-fingerprint';
        $firstResponse = $this->postJson(
            self::TEST_ENDPOINT,
            ['data' => 'first_fingerprint_test'],
            ['X-Fingerprint' => $firstFingerprint]
        );
        $firstResponse->assertStatus(200);

        // Second fingerprint with burst access pattern
        $secondFingerprint = 'second-test-fingerprint';
        for ($i = 0; $i < 5; $i++) {
            $this->postJson(
                self::TEST_ENDPOINT,
                ['data' => "second_fingerprint_$i"],
                ['X-Fingerprint' => $secondFingerprint]
            );
        }

        // Verify first fingerprint is still allowed with normal score
        $finalFirstResponse = $this->postJson(
            self::TEST_ENDPOINT,
            ['data' => 'first_fingerprint_final'],
            ['X-Fingerprint' => $firstFingerprint]
        );
        $finalFirstResponse->assertStatus(200);

        // Verify scores are isolated between fingerprints
        $dataStore = $this->app->make(DataStore::class);
        $firstScoreKey = 'citadel:request_score:'.$firstFingerprint;
        $secondScoreKey = 'citadel:request_score:'.$secondFingerprint;

        $firstScore = $dataStore->getValue($firstScoreKey);
        $secondScore = $dataStore->getValue($secondScoreKey);

        $this->assertLessThan($secondScore, $firstScore, 'First fingerprint should have lower score than the burst one');
    }
}
