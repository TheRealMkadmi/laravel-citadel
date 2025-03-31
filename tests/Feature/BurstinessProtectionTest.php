<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\Tests\TestCase;

class BurstinessProtectionTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Middleware group name for route protection
     */
    private const MIDDLEWARE_GROUP = 'citadel-protect';

    protected function setUp(): void
    {
        parent::setUp();

        // Configure burst protection settings
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true);

        // The BurstinessAnalyzer is now enabled in TestCase::getEnvironmentSetUp
        // so we don't need to enable it here anymore

        // Set up test routes (moved to getEnvironmentSetUp to ensure config is applied first)
        // $this->setupTestRoutes();
    }

    protected function setupTestRoutes(): void
    {
        // Create a test route with the protection middleware
        Route::middleware(self::MIDDLEWARE_GROUP)->get('/test-protected', function () {
            return response()->json(['success' => true, 'message' => 'Protected route accessed']);
        })->name('test.protected');

        // Create a route without protection for comparison
        Route::get('/test-unprotected', function () {
            return response()->json(['success' => true, 'message' => 'Unprotected route accessed']);
        })->name('test.unprotected');
    }

    /**
     * Helper method to make requests appear to come from same client
     */
    protected function makeConsistentRequest(string $route, string $fingerprint = 'test-feature-fingerprint-12345')
    {
        // Fetch the configured header name
        $headerName = Config::get(CitadelConfig::KEY_HEADER.'.name', 'X-Fingerprint');

        return $this->withHeaders([
            'User-Agent' => 'PHPUnit Test Client',
            $headerName => $fingerprint, // Use the actual header name
        ])->get($route);
    }

    #[Test]
    public function protected_route_can_be_accessed_normally()
    {
        // A single request should always pass
        $response = $this->makeConsistentRequest('/test-protected');

        $response->assertStatus(200)
            ->assertJson(['success' => true]);
    }

    #[Test]
    public function burst_requests_to_protected_route_should_be_blocked()
    {
        // Configure for quicker blocking - set threshold lower than BurstinessAnalyzer scores
        $threshold = 30.0; // BurstinessAnalyzer returns scores up to 50.0 for burst patterns
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, $threshold);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 40.0); // Ensure score exceeds threshold

        // First few requests should pass
        $response1 = $this->makeConsistentRequest('/test-protected');
        $response1->assertStatus(200);

        // Make several quick requests
        $response2 = $this->makeConsistentRequest('/test-protected');
        $response2->assertStatus(200);

        $response3 = $this->makeConsistentRequest('/test-protected');

        $response4 = $this->makeConsistentRequest('/test-protected');

        // One more rapid request should trigger blocking
        $response5 = $this->makeConsistentRequest('/test-protected');

        // Eventually, requests should be blocked due to burstiness
        $response6 = $this->makeConsistentRequest('/test-protected');

        // Log response statuses to help with debugging
        Log::debug('Citadel Test: Request responses', [
            'response1' => $response1->status(),
            'response2' => $response2->status(),
            'response3' => $response3->status(),
            'response4' => $response4->status(),
            'response5' => $response5->status(),
            'response6' => $response6->status(),
            'threshold' => $threshold,
        ]);

        // At least one of the later responses should be blocked (403 Forbidden)
        // We can't be 100% deterministic about which one due to caching and timing
        $blocked = $response4->status() == 403 ||
                  $response5->status() == 403 ||
                  $response6->status() == 403;

        $this->assertTrue($blocked, 'Expected at least one request to be blocked after multiple rapid requests, but none were blocked.');
    }

    #[Test]
    public function unprotected_route_allows_burst_requests()
    {
        // Make several quick requests to an unprotected route
        for ($i = 0; $i < 6; $i++) {
            $response = $this->makeConsistentRequest('/test-unprotected');
            $response->assertStatus(200);
        }
    }

    #[Test]
    public function analyzer_integration_with_middleware_works_correctly()
    {
        // Configure a low threshold for easier testing
        $threshold = 20.0; // Lower threshold to ensure blocking occurs
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, $threshold);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.max_requests_per_window', 3); // Lower max requests
        Config::set(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 30.0); // Ensure burst hits threshold

        // Add a slight delay between setup and test to ensure clean state
        usleep(100000); // 100ms delay

        $fingerprint = 'test-middleware-integration-'.uniqid();

        // First request should always pass
        $res1 = $this->makeConsistentRequest('/test-protected', $fingerprint);
        $res1->assertStatus(200);

        // Add a delay between requests to avoid triggering burst detection prematurely
        usleep(500000); // 500ms delay

        // Second request should pass
        $res2 = $this->makeConsistentRequest('/test-protected', $fingerprint);
        $res2->assertStatus(200);

        // The third request may either pass or be blocked depending on timing
        // So we don't assert its status directly
        $res3 = $this->makeConsistentRequest('/test-protected', $fingerprint);

        // Make additional requests to ensure blocking occurs
        $response4 = $this->makeConsistentRequest('/test-protected', $fingerprint);

        // If the 3rd or 4th wasn't blocked, try a 5th request
        $response5 = null;
        if ($res3->status() !== 403 && $response4->status() !== 403) {
            $response5 = $this->makeConsistentRequest('/test-protected', $fingerprint);
        }

        // Log response statuses for debugging
        Log::debug('Citadel Test: Integration test responses', [
            'res1' => $res1->status(),
            'res2' => $res2->status(),
            'res3' => $res3->status(),
            'response4' => $response4->status(),
            'response5' => $response5 ? $response5->status() : 'not sent',
            'threshold' => $threshold,
            'fingerprint' => $fingerprint,
        ]);

        // Assert that at least one of the requests is blocked (403 Forbidden)
        $blocked = $res3->status() === 403 ||
                  $response4->status() === 403 ||
                  ($response5 !== null && $response5->status() === 403);

        $this->assertTrue($blocked, 'Expected at least one request to be blocked due to burst/excess requests, but none were blocked.');
    }

    #[Test]
    public function normal_request_pattern_allows_access()
    {
        // Access the protected route with normal timing
        $response1 = $this->makeConsistentRequest('/test-protected');
        $response1->assertStatus(200);

        // Wait before next request
        sleep(2);
        $response2 = $this->makeConsistentRequest('/test-protected');
        $response2->assertStatus(200);

        // Wait again
        sleep(2);
        $response3 = $this->makeConsistentRequest('/test-protected');

        // Normally spaced requests should never be blocked
        $response3->assertStatus(200);
    }
}
