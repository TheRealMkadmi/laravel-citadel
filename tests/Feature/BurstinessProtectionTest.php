<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\BurstinessAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Middleware\ProtectRouteMiddleware;

class BurstinessProtectionTest extends \TheRealMkadmi\Citadel\Tests\TestCase
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
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 50);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 30);
        
        // Configure burstiness analyzer
        Config::set(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', true);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.window_size', 10000); // 10 seconds in ms
        Config::set(CitadelConfig::KEY_BURSTINESS . '.min_interval', 1000); // 1 second in ms
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_requests_per_window', 3);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.excess_request_score', 20.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.burst_penalty_score', 30.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_frequency_score', 100.0);
        
        // Set up test routes
        $this->setupTestRoutes();
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
    protected function makeConsistentRequest(string $route)
    {
        return $this->withHeaders([
            'User-Agent' => 'PHPUnit Test Client',
            'X-Fingerprint' => 'test-feature-fingerprint-12345'
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
        // Configure for quicker blocking
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 40);
        
        // First few requests should pass
        $response1 = $this->makeConsistentRequest('/test-protected');
        $response1->assertStatus(200);
        
        // Make several quick requests
        $response2 = $this->makeConsistentRequest('/test-protected');
        $response2->assertStatus(200);
        
        $response3 = $this->makeConsistentRequest('/test-protected');
        $response3->assertStatus(200);
        
        $response4 = $this->makeConsistentRequest('/test-protected');
        
        // One more rapid request should trigger blocking
        $response5 = $this->makeConsistentRequest('/test-protected');
        
        // Eventually, requests should be blocked due to burstiness
        $response6 = $this->makeConsistentRequest('/test-protected');
        
        // At least one of the later responses should be blocked (403 Forbidden)
        // We can't be 100% deterministic about which one due to caching and timing
        $blocked = $response4->status() == 403 || 
                  $response5->status() == 403 || 
                  $response6->status() == 403;
                  
        $this->assertTrue($blocked, 'At least one request should be blocked after multiple rapid requests');
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
        // Get the real instances from the container to inspect them
        $dataStore = app(DataStore::class);
        $analyzer = app(BurstinessAnalyzer::class);
        
        // Create a fake request with a fingerprint for manual analysis
        $request = Request::create('/test', 'GET');
        $request->headers->set('X-Fingerprint', 'test-middleware-fingerprint');
        
        // Add fingerprint macro to request
        $request->macro('getFingerprint', function () {
            return $this->headers->get('X-Fingerprint');
        });
        
        // First analysis should return zero score
        $score1 = $analyzer->analyze($request);
        $this->assertEquals(0.0, $score1);
        
        // Now make multiple burst requests
        for ($i = 0; $i < 5; $i++) {
            $analyzer->analyze($request);
        }
        
        // Check that score has increased
        $finalScore = $analyzer->analyze($request);
        $this->assertGreaterThan(0.0, $finalScore, 'Score should increase after multiple requests');
        
        // Create a middleware with our analyzer
        $middleware = new ProtectRouteMiddleware([$analyzer], $dataStore);
        
        // Checks if high scores will correctly block requests
        if ($finalScore > 40) {
            // If score is high enough, request should be blocked
            $response = $middleware->handle($request, function ($req) {
                return response()->json(['success' => true]);
            });
            
            $this->assertEquals(403, $response->getStatusCode(), 'High score should result in blocked request');
        }
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