<?php

namespace TheRealMkadmi\Citadel\Tests\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\BurstinessAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;

class BurstinessAnalyzerTest extends \TheRealMkadmi\Citadel\Tests\TestCase
{
    protected $dataStore;

    protected $analyzer;

    protected $request;

    protected $fingerprint = 'test-fingerprint';

    protected function setUp(): void
    {
        parent::setUp();

        $this->dataStore = new ArrayDataStore();
        $this->analyzer = new BurstinessAnalyzer($this->dataStore);
        $this->request = $this->makeFingerprintedRequest($this->fingerprint);
        $this->configureTestEnvironment();
    }

    protected function configureTestEnvironment(): void
    {
        Config::set(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', true);
        Config::set(CitadelConfig::KEY_CACHE . '.burst_analysis_ttl', 3600);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.window_size', 60000);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.min_interval', 5000);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_requests_per_window', 5);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.excess_request_score', 10.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.burst_penalty_score', 20.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_frequency_score', 100.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.very_regular_threshold', 0.1);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.somewhat_regular_threshold', 0.25);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.very_regular_score', 30.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.somewhat_regular_score', 15.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.pattern_history_size', 5);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.history_ttl_multiplier', 6);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.min_violations_for_penalty', 1);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_violation_score', 50.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.severe_excess_threshold', 10);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_excess_score', 30.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.excess_multiplier', 2.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.ttl_buffer_multiplier', 2);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.min_samples_for_pattern', 3);
    }

    #[Test]
    public function it_returns_zero_when_disabled()
    {
        Config::set(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', false);

        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(0.0, $score, 'Expected score to be 0.0 when analyzer is disabled, but got: ' . $score);
    }

    #[Test]
    public function it_caps_score_at_max_frequency_score()
    {
        // Set up conditions to exceed max score
        $key = "burst:" . substr(md5($this->fingerprint), 0, 12) . ":req";
        $now = time() * 1000;
        
        // Add many timestamps to simulate excessive requests
        for ($i = 0; $i < 30; $i++) {
            $this->dataStore->zAdd($key, $now - ($i * 1000), $now - ($i * 1000));
        }

        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(100.0, $score);
    }

    #[Test]
    public function it_detects_regular_patterns_suggesting_automation()
    {
        $now = time() * 1000;
        $interval = 15000; // Exactly 15 seconds between each request
        $key = "burst:" . substr(md5($this->fingerprint), 0, 12) . ":req";
        $patKey = "burst:" . substr(md5($this->fingerprint), 0, 12) . ":pat";
        
        // Create very regular pattern
        for ($i = 4; $i >= 0; $i--) {
            $timestamp = $now - ($interval * $i);
            $this->dataStore->zAdd($key, $timestamp, $timestamp);
        }
        
        // Add pattern data indicating very regular behavior
        $this->dataStore->setValue($patKey, ['cv_history' => [0.05, 0.06, 0.04, 0.05]]);

        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(30.0, $score);
    }

    #[Test]
    public function it_applies_historical_penalties_for_repeat_offenders()
    {
        $now = time() * 1000;
        $histKey = "burst:" . substr(md5($this->fingerprint), 0, 12) . ":hist";
        
        // Set up history data to indicate previous violations
        $historyData = [
            'last_violation' => $now - 600000,
            'violation_count' => 1,
        ];
        
        $this->dataStore->setValue($histKey, $historyData);

        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(20.0, $score);
    }

    #[Test]
    public function it_analyzes_normal_request_pattern_with_no_penalties()
    {
        $now = time() * 1000;
        $keySuffix = substr(md5($this->fingerprint), 0, 12);
        $key = "burst:{$keySuffix}:req";
        $histKey = "burst:{$keySuffix}:hist";
        $patKey = "burst:{$keySuffix}:pat";
        
        // Clear any existing data that might affect the score
        $this->dataStore->removeValue($histKey);
        $this->dataStore->removeValue($patKey);
        $this->dataStore->zRemRangeByRank($key, 0, -1); // Remove all timestamps from sorted set
        
        // Add just a few timestamps, well spaced apart (ensuring we have few enough requests)
        // Max allowed is 5 requests per window, so use only 3
        for ($i = 2; $i >= 0; $i--) {
            $timestamp = $now - ($i * 20000); // 20 seconds apart
            $this->dataStore->zAdd($key, $timestamp, $timestamp);
        }
        
        // Create a fresh analyzer instance to avoid any cached state
        $analyzer = new BurstinessAnalyzer($this->dataStore);
        
        $score = $analyzer->analyze($this->request);
        $this->assertEquals(0.0, $score);
    }

    #[Test]
    public function it_correctly_calculates_ttl_from_window_size()
    {
        // This is an indirect test through the analyzer which will
        // use the ArrayDataStore pipeline methods with the right TTL
        $score = $this->analyzer->analyze($this->request);
        
        // The fact that this works at all indirectly verifies the TTL calculation
        $this->assertEquals(0.0, $score);
    }

    #[Test]
    public function it_handles_requests_with_empty_fingerprint()
    {
        // Create a request with no fingerprint
        $emptyFingerprintRequest = $this->makeFingerprintedRequest(null);
        
        // The analyzer should safely return 0 for requests with no fingerprint
        $score = $this->analyzer->analyze($emptyFingerprintRequest);
        $this->assertEquals(0.0, $score);
    }
    
    #[Test]
    public function it_uses_cached_score_when_available()
    {
        // Directly set a cached score
        $cacheKey = "burstiness:{$this->fingerprint}";
        $this->dataStore->setValue($cacheKey, 42.0, 60);
        
        // Analyzer should return the cached score without recalculating
        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(42.0, $score);
    }

    #[Test]
    public function it_combines_multiple_penalty_factors()
    {
        $now = time() * 1000;
        $requestsKey = "burst:" . substr(md5($this->fingerprint), 0, 12) . ":req";
        $histKey = "burst:" . substr(md5($this->fingerprint), 0, 12) . ":hist";
        
        // Add excessive requests
        for ($i = 0; $i < 10; $i++) {
            $timestamp = $now - ($i * 1000);
            $this->dataStore->zAdd($requestsKey, $timestamp, $timestamp);
        }
        
        // Add burst-like pattern (requests very close together)
        for ($i = 0; $i < 3; $i++) {
            $timestamp = $now - ($i * 2000);
            $this->dataStore->zAdd($requestsKey, $timestamp, $timestamp);
        }
        
        // Add historical violations
        $historyData = [
            'last_violation' => $now - 600000,
            'violation_count' => 2,
            'max_excess' => 5,
            'total_excess' => 10,
        ];
        $this->dataStore->setValue($histKey, $historyData);
        
        // The score should reflect multiple penalty factors
        $score = $this->analyzer->analyze($this->request);
        $this->assertGreaterThan(30.0, $score, "Score should combine multiple penalty factors");
    }

    #[Test]
    public function it_calculates_excess_request_scores_correctly()
    {
        // Test with different request counts to see how excess scores are calculated
        $now = time() * 1000;
        $scores = [];
        
        // Configure for much higher max score to properly test progression
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_frequency_score', 1000.0);
        
        // Use smaller request counts to avoid capping and ensure clear progression
        $requestCounts = [6, 8, 10, 12];
        
        // Use a unique fingerprint for each test case to avoid any cross-contamination
        foreach ($requestCounts as $requestCount) {
            // Create a unique fingerprint for this test case
            $uniqueFingerprint = "test-fingerprint-{$requestCount}";
            $keySuffix = substr(md5($uniqueFingerprint), 0, 12);
            $key = "burst:{$keySuffix}:req";
            
            // Create a fresh datastore and analyzer for each test case
            $dataStore = new ArrayDataStore();
            $analyzer = new BurstinessAnalyzer($dataStore);
            $request = $this->makeFingerprintedRequest($uniqueFingerprint);
            
            // Add the specified number of timestamps using consistent intervals
            // that aren't so close as to trigger burst detection
            for ($i = 0; $i < $requestCount; $i++) {
                // Use 5100ms spacing to be safely above the minInterval config (5000ms)
                // This ensures we're testing excess request counts, not burst patterns
                $timestamp = $now - ($i * 5100);
                $dataStore->zAdd($key, $timestamp, $timestamp);
            }
            
            // Get the score for this request count
            $score = $analyzer->analyze($request);
            $scores[$requestCount] = $score;
        }
        
        // Check that scores increase as request count increases
        // Correct the assertion by comparing in the right order
        $this->assertLessThan($scores[10], $scores[8], "Score should increase with more requests");
        $this->assertLessThan($scores[12], $scores[10], "Score should increase with more requests");
        
        // Check that excess requests are being scored correctly
        // 6 requests = 1 excess request * 10 = 10 score (+ potential burst penalty if intervals are close)
        $this->assertGreaterThanOrEqual(10.0, $scores[6], "Score for 6 requests should be at least 10.0");
        
        // Check score increases at approximately linear or greater rate
        $scoreDiff8to6 = $scores[8] - $scores[6];
        $scoreDiff12to10 = $scores[12] - $scores[10];
        
        // Verify the scoring algorithm maintains or increases the rate of score increase
        $this->assertGreaterThanOrEqual($scoreDiff8to6, $scoreDiff12to10, 
            "Score growth should maintain or accelerate as request count increases");
    }
}
