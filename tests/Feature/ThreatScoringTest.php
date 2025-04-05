<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\BurstinessAnalyzer;
use TheRealMkadmi\Citadel\Analyzers\SpamminessAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Middleware\ProtectRouteMiddleware;
use TheRealMkadmi\Citadel\Tests\TestCase;

class ThreatScoringTest extends TestCase
{
    protected ArrayDataStore $dataStore;
    protected ProtectRouteMiddleware $middleware;
    protected const TEST_FINGERPRINT = 'test-fingerprint-12345';
    protected const HIGH_THRESHOLD = 50.0;
    protected const LOW_THREAT_SCORE = 5.0;
    protected const HIGH_THREAT_SCORE = 40.0;
    protected const WARNING_THRESHOLD = 20.0;
    protected const MIDDLEWARE_CACHE_TTL = 3600;

    protected function setUp(): void
    {
        parent::setUp();

        // Set up DataStore with a fresh instance for each test
        $this->dataStore = new ArrayDataStore();
        $this->app->instance(DataStore::class, $this->dataStore);
        $this->app->instance(ArrayDataStore::class, $this->dataStore);

        // Ensure middleware is enabled for tests
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true);
    }

    /**
     * Creates an analyzer that always returns a specific score for testing
     */
    private function createFixedScoreAnalyzer(float $fixedScore): BurstinessAnalyzer
    {
        // Create a real BurstinessAnalyzer with modified config for predictable scoring
        $analyzer = new BurstinessAnalyzer($this->dataStore);
        
        // Configure analyzer to return our desired score
        if ($fixedScore > 0) {
            // For a high score: set up extreme burstiness detection
            Config::set(CitadelConfig::KEY_BURSTINESS.'.max_requests_per_window', 1);
            Config::set(CitadelConfig::KEY_BURSTINESS.'.window_size', 60000);
            Config::set(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', $fixedScore);
        } else {
            // For a zero score: disable burstiness detection
            Config::set(CitadelConfig::KEY_BURSTINESS.'.enable_burstiness_analyzer', false);
        }
        
        return $analyzer;
    }

    /**
     * Helper function to create analyzers array with fixed scores for testing
     * 
     * @param array $scores An array of fixed scores to use for the analyzers
     * @return array Configured analyzers array for the middleware
     */
    private function createAnalyzersArrayWithFixedScores(array $scores): array
    {
        $analyzers = [];
        
        foreach ($scores as $score) {
            $analyzers[] = $this->createFixedScoreAnalyzer($score);
        }
        
        return [
            'all' => $analyzers,
            'body_analyzers' => [],
            'external_resource_analyzers' => []
        ];
    }

    #[Test]
    public function middleware_allows_request_when_score_below_threshold()
    {
        // Configure analyzers with low scores
        $analyzers = $this->createAnalyzersArrayWithFixedScores([
            self::LOW_THREAT_SCORE, self::LOW_THREAT_SCORE
        ]);

        // Set threshold to a higher value than the sum of analyzer scores
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, self::HIGH_THRESHOLD);

        // Create middleware with real analyzers
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);

        // Create a request to analyze
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Apply middleware
        $response = $middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify request is allowed through
        $this->assertEquals('allowed', $response);
    }

    #[Test]
    public function middleware_blocks_request_when_score_exceeds_threshold()
    {
        // Configure analyzers with high scores
        $analyzers = $this->createAnalyzersArrayWithFixedScores([
            self::HIGH_THREAT_SCORE, self::HIGH_THREAT_SCORE
        ]);

        // Set threshold to a value that will be exceeded by the analyzer scores
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, self::HIGH_THRESHOLD);

        // Create middleware with real analyzers
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);

        // Create a request to analyze
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Apply middleware
        $response = $middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify request is blocked (not allowed through)
        $this->assertNotEquals('allowed', $response);
        
        // Verify the response is a 403 Forbidden
        $this->assertEquals(403, $response->getStatusCode());
    }

    #[Test]
    public function middleware_only_uses_appropriate_analyzers_for_request()
    {
        // Create BurstinessAnalyzer (standard, no request body needed)
        $standardAnalyzer = $this->createFixedScoreAnalyzer(10.0);
        
        // Create SpamminessAnalyzer (requires request body)
        $bodyAnalyzer = new SpamminessAnalyzer($this->dataStore);
        
        // Configure IpAnalyzer to use external resources
        Config::set('citadel.ip.enable_ip_analyzer', true);
        $externalAnalyzer = $this->app->make('TheRealMkadmi\Citadel\Analyzers\IpAnalyzer');

        $analyzers = [
            'all' => [$standardAnalyzer, $bodyAnalyzer, $externalAnalyzer],
            'body_analyzers' => [$bodyAnalyzer],
            'external_resource_analyzers' => [$externalAnalyzer],
        ];

        // Configure middleware settings
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, self::HIGH_THRESHOLD);
        Config::set(CitadelConfig::KEY_MIDDLEWARE.'.analyze_request_body', false);
        Config::set(CitadelConfig::KEY_MIDDLEWARE.'.use_external_analyzers', false);

        // Create middleware with real analyzers
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);

        // Create a request to analyze
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Apply middleware
        $middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify we have a score (only from the standard analyzer)
        $totalScore = $this->dataStore->getValue('citadel:request_score:' . self::TEST_FINGERPRINT);
        $this->assertEquals(10.0, $totalScore);
    }

    #[Test]
    public function middleware_caches_analysis_results()
    {
        // Create a real analyzer
        $analyzer = new BurstinessAnalyzer($this->dataStore);
        
        // Set up the analyzers array
        $analyzers = [
            'all' => [$analyzer],
            'body_analyzers' => [],
            'external_resource_analyzers' => [],
        ];

        // Configure middleware settings
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, self::HIGH_THRESHOLD);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_CACHE_TTL, self::MIDDLEWARE_CACHE_TTL);

        // Create middleware with real analyzer
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);

        // Create a request with a consistent fingerprint
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Process the request first time
        $middleware->handle($request, function ($req) {
            return 'allowed';
        });
        
        // Get the current score key
        $scoreKey = 'citadel:request_score:' . self::TEST_FINGERPRINT;
        $initialScore = $this->dataStore->getValue($scoreKey);
        
        // Manipulate the score directly to test caching
        $this->dataStore->setValue($scoreKey, 15.0);

        // Process the request again - should use cached value
        $middleware->handle($request, function ($req) {
            return 'allowed';
        });
        
        // Check that the value remains the manipulated one (15.0) due to caching
        $cachedScore = $this->dataStore->getValue($scoreKey);
        $this->assertEquals(15.0, $cachedScore);
    }

    #[Test]
    public function middleware_responds_appropriately_to_warning_threshold()
    {
        // Create analyzer with score between warning threshold and blocking threshold
        $warningAnalyzer = $this->createFixedScoreAnalyzer(30.0);

        $analyzers = [
            'all' => [$warningAnalyzer],
            'body_analyzers' => [],
            'external_resource_analyzers' => [],
        ];

        // Set up thresholds for warning vs blocking
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, self::HIGH_THRESHOLD);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, self::WARNING_THRESHOLD);

        // Create middleware with real analyzer
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);

        // Create a request to analyze
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Apply middleware
        $response = $middleware->handle($request, function ($req) {
            return response('allowed');
        });

        // Request should be allowed but with warning headers
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue($response->headers->has('X-Threat-Detected'));
    }

    #[Test]
    public function middleware_respects_disabled_setting()
    {
        // Create high-scoring analyzer
        $highScoreAnalyzer = $this->createFixedScoreAnalyzer(100.0);

        $analyzers = [
            'all' => [$highScoreAnalyzer],
            'body_analyzers' => [],
            'external_resource_analyzers' => [],
        ];

        // Disable middleware
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, false);

        // Create middleware with real analyzer
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);

        // Create a request to analyze
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Apply middleware
        $response = $middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify request is allowed through despite high score
        $this->assertEquals('allowed', $response);
    }

    #[Test]
    public function middleware_behavior_respects_various_config_settings()
    {
        // Create high-scoring analyzer
        $highScoreAnalyzer = $this->createFixedScoreAnalyzer(100.0);

        $analyzers = [
            'all' => [$highScoreAnalyzer],
            'body_analyzers' => [],
            'external_resource_analyzers' => [],
        ];

        // Test 1: When threshold is higher than analyzer score
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 150.0);  // Higher than our analyzer's score

        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);
        
        $response = $middleware->handle($request, function ($req) {
            return 'allowed';
        });
        
        $this->assertEquals('allowed', $response, 'Request should be allowed when score is below threshold');
        
        // Test 2: When warning threshold is lower than analyzer score but block threshold is higher
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 150.0);  // Higher than analyzer's score
        Config::set(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 50.0);  // Lower than analyzer's score
        
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);
        $request = $this->makeFingerprintedRequest('warning-test-fingerprint');
        
        $response = $middleware->handle($request, function ($req) {
            return response('allowed');
        });
        
        $this->assertEquals(200, $response->getStatusCode(), 'Request should be allowed when score is above warning but below blocking');
        $this->assertTrue($response->headers->has('X-Threat-Detected'), 'Response should have warning headers when score exceeds warning threshold');
        
        // Test 3: With auto-banning enabled
        Config::set(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 50.0);  // Lower than analyzer's score
        Config::set(CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_BAN_DURATION, 60); // 1 minute ban
        
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);
        $banFingerprint = 'auto-ban-fingerprint';
        $banRequest = $this->makeFingerprintedRequest($banFingerprint);
        
        $response = $middleware->handle($banRequest, function ($req) {
            return 'this should never run';
        });
        
        $this->assertNotEquals('this should never run', $response, 'Request should be blocked when score exceeds threshold');
        $this->assertEquals(403, $response->getStatusCode(), 'Response should be 403 Forbidden');
        
        // Verify that the fingerprint was automatically banned
        $banKey = 'citadel:ban:fingerprint:' . $banFingerprint;
        $banData = $this->dataStore->getValue($banKey);
        $this->assertNotNull($banData, 'Fingerprint should be banned when auto-ban is enabled');
    }

    #[Test]
    public function middleware_caches_scores_for_configurable_duration()
    {
        // Create a mild-scoring analyzer
        $mildAnalyzer = $this->createFixedScoreAnalyzer(10.0);
        
        $analyzers = [
            'all' => [$mildAnalyzer],
            'body_analyzers' => [],
            'external_resource_analyzers' => [],
        ];

        // Set a short cache TTL for testing
        $cacheTtl = 2; // 2 seconds
        Config::set(CitadelConfig::KEY_MIDDLEWARE_CACHE_TTL, $cacheTtl);
        
        // Create middleware with our analyzer
        $middleware = new ProtectRouteMiddleware($analyzers, $this->dataStore);
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);
        
        // First request should process normally
        $middleware->handle($request, function ($req) {
            return 'allowed';
        });
        
        // Score should be cached
        $scoreKey = 'citadel:request_score:' . self::TEST_FINGERPRINT;
        $cachedScore = $this->dataStore->getValue($scoreKey);
        $this->assertEquals(10.0, $cachedScore, 'Score should be cached after request');
        
        // Modify the cached score to verify it's being used
        $this->dataStore->setValue($scoreKey, 25.0);
        
        // Request again immediately - should use cached score without re-analyzing
        $middleware->handle($request, function ($req) {
            return 'allowed';
        });
        
        // Cached score should remain our modified value
        $this->assertEquals(25.0, $this->dataStore->getValue($scoreKey), 'Middleware should use cached score within TTL period');
        
        // Wait for TTL to expire
        sleep($cacheTtl + 1);
        
        // Request again - should recalculate score
        $middleware->handle($request, function ($req) {
            return 'allowed';
        });
        
        // Should have fresh score, not our modified value
        $this->assertEquals(10.0, $this->dataStore->getValue($scoreKey), 'Score should be recalculated after cache TTL expires');
    }
}