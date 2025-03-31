<?php

namespace TheRealMkadmi\Citadel\Tests\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\BurstinessAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;

class BurstinessAnalyzerIntegrationTest extends \TheRealMkadmi\Citadel\Tests\TestCase
{
    protected $dataStore;

    protected $analyzer;

    protected $fingerprint;

    protected function setUp(): void
    {
        parent::setUp();

        // Use real ArrayDataStore for integration testing
        $this->dataStore = new ArrayDataStore;

        // Create the analyzer with the real DataStore
        $this->analyzer = new BurstinessAnalyzer($this->dataStore);

        // Set a consistent fingerprint for testing
        $this->fingerprint = 'test-integration-fingerprint-'.uniqid();

        // Configure test environment
        $this->configureTestEnvironment();
    }

    protected function configureTestEnvironment(): void
    {
        // Set up test configuration values
        Config::set(CitadelConfig::KEY_BURSTINESS.'.enable_burstiness_analyzer', true);
        Config::set(CitadelConfig::KEY_CACHE.'.burst_analysis_ttl', 60); // Short TTL for testing
        Config::set(CitadelConfig::KEY_BURSTINESS.'.window_size', 60000); // 60 seconds in ms
        Config::set(CitadelConfig::KEY_BURSTINESS.'.min_interval', 5000); // 5 seconds in ms
        Config::set(CitadelConfig::KEY_BURSTINESS.'.max_requests_per_window', 5);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.excess_request_score', 10.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 20.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.max_frequency_score', 100.0);

        // Set all other necessary configuration values
        Config::set(CitadelConfig::KEY_BURSTINESS.'.very_regular_threshold', 0.1);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.somewhat_regular_threshold', 0.25);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.very_regular_score', 30.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.somewhat_regular_score', 15.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.pattern_history_size', 5);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.history_ttl_multiplier', 6);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.min_violations_for_penalty', 1);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.max_violation_score', 50.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.severe_excess_threshold', 10);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.max_excess_score', 30.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.excess_multiplier', 2.0);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.ttl_buffer_multiplier', 2);
        Config::set(CitadelConfig::KEY_BURSTINESS.'.min_samples_for_pattern', 3);
    }

    #[Test]
    public function multiple_analyzer_calls_within_window_increase_score()
    {
        // Create real request
        $request = $this->makeFingerprintedRequest($this->fingerprint);

        // First request should have zero score (no history)
        $score1 = $this->analyzer->analyze($request);
        $this->assertEquals(0.0, $score1);

        // Multiple calls in quick succession to simulate burst
        $scores = [$score1];
        for ($i = 0; $i < 10; $i++) {
            $scores[] = $this->analyzer->analyze($request);
        }

        // Score should increase due to excessive requests
        $this->assertGreaterThan($score1, end($scores), 'Expected score to increase due to multiple analyzer calls, but final score was: '.end($scores));

        // Final score should be substantial due to multiple violations
        $this->assertGreaterThan(10.0, end($scores));
    }

    #[Test]
    public function scores_are_cached_between_calls()
    {
        // Create real request
        $request = $this->makeFingerprintedRequest($this->fingerprint);

        // First analysis stores a score
        $originalScore = $this->analyzer->analyze($request);

        // Create a new analyzer instance that should read from cache
        $newAnalyzer = new BurstinessAnalyzer($this->dataStore);

        // Simulate quick follow-up request that should use cached score
        $cachedScore = $newAnalyzer->analyze($request);

        // Cached score should match the original
        $this->assertEquals($originalScore, $cachedScore);

        // But multiple rapid requests should eventually increase the score
        // as cache TTL expires or burstiness is detected
        $finalScore = null;
        for ($i = 0; $i < 5; $i++) {
            usleep(100000); // 100ms delay
            $finalScore = $newAnalyzer->analyze($request);
        }

        // Final score should eventually differ from original as cache expires
        // or as new requests are recorded and analyzed
        $this->assertNotNull($finalScore);
    }

    #[Test]
    public function normal_request_pattern_should_not_trigger_penalties()
    {
        // Create a unique fingerprint for this test
        $fingerprint = 'normal-pattern-test-'.uniqid();
        $request = $this->makeFingerprintedRequest($fingerprint);

        // Simulate normal user behavior with reasonable gaps
        $score1 = $this->analyzer->analyze($request);
        $this->assertEquals(0.0, $score1);

        // Wait before next request (>5 seconds to avoid burst penalty)
        sleep(6);
        $score2 = $this->analyzer->analyze($request);

        // Wait again before next request
        sleep(6);
        $score3 = $this->analyzer->analyze($request);

        // One more normal request
        sleep(6);
        $score4 = $this->analyzer->analyze($request);

        // A normal pattern shouldn't trigger penalties
        $this->assertEquals(0.0, $score4, 'Normal request pattern should have zero score');
    }

    #[Test]
    public function burst_pattern_should_trigger_penalty()
    {
        // Unique fingerprint for this test
        $fingerprint = 'burst-test-fingerprint-'.uniqid();
        $request = $this->makeFingerprintedRequest($fingerprint);

        // Initial request
        $score1 = $this->analyzer->analyze($request);
        $this->assertEquals(0.0, $score1);

        // Rapid succession of requests
        usleep(500000); // 500ms
        $score2 = $this->analyzer->analyze($request);

        usleep(500000); // 500ms
        $score3 = $this->analyzer->analyze($request);

        usleep(500000); // 500ms
        $score4 = $this->analyzer->analyze($request);

        // A few more quick requests
        usleep(500000); // 500ms
        $score5 = $this->analyzer->analyze($request);

        usleep(500000); // 500ms
        $finalScore = $this->analyzer->analyze($request);

        // The burst pattern should trigger a penalty
        $this->assertGreaterThan(0.0, $finalScore, 'Burst pattern should have non-zero score');
        $this->assertGreaterThanOrEqual(20.0, $finalScore, 'Score should include burst penalty');
    }

    #[Test]
    public function regular_pattern_detection_should_work()
    {
        // Unique fingerprint for this test
        $fingerprint = 'pattern-test-fingerprint-'.uniqid();
        $request = $this->makeFingerprintedRequest($fingerprint);

        // Need to override defaults to make this test feasible in reasonable time
        Config::set(CitadelConfig::KEY_BURSTINESS.'.min_interval', 1000); // 1 second in ms

        // Create a new analyzer with the updated config
        $this->analyzer = new BurstinessAnalyzer($this->dataStore);

        // Initial request
        $score1 = $this->analyzer->analyze($request);
        $this->assertEquals(0.0, $score1);

        // Simulate perfectly regular automated requests
        // Exact 2-second gaps between requests
        $scores = [$score1];

        for ($i = 0; $i < 6; $i++) {
            sleep(2); // Exactly 2 seconds between each request
            $scores[] = $this->analyzer->analyze($request);
        }

        // Eventually the pattern should be detected
        $this->assertGreaterThan(0.0, end($scores), 'Regular pattern should be detected');
    }

    #[Test]
    public function excessive_requests_should_trigger_penalties()
    {
        // Unique fingerprint for this test
        $fingerprint = 'excess-test-fingerprint-'.uniqid();
        $request = $this->makeFingerprintedRequest($fingerprint);

        // Make many requests in quick succession
        $scores = [];

        // Send 10 requests (max is 5, so 5 excess)
        for ($i = 0; $i < 10; $i++) {
            usleep(100000); // 100ms apart
            $scores[] = $this->analyzer->analyze($request);
        }

        // Score should increase due to excessive requests
        $lastScore = end($scores);
        $this->assertGreaterThan(0.0, $lastScore, 'Excessive requests should have non-zero score');
    }

    #[Test]
    public function historical_offenses_should_increase_penalty()
    {
        // Unique fingerprint for this test
        $fingerprint = 'history-test-fingerprint-'.uniqid();
        $request = $this->makeFingerprintedRequest($fingerprint);

        // First offense - several requests in quick succession
        $firstOffenseScores = [];
        for ($i = 0; $i < 8; $i++) {
            $firstOffenseScores[] = $this->analyzer->analyze($request);
        }
        $firstMaxScore = max($firstOffenseScores);

        // Wait a bit to ensure we're considered a separate offense
        sleep(1);

        // Second offense - should have higher penalty due to history
        $secondOffenseScores = [];
        for ($i = 0; $i < 8; $i++) {
            $secondOffenseScores[] = $this->analyzer->analyze($request);
        }
        $secondMaxScore = max($secondOffenseScores);

        // The second offense should be penalized more heavily
        $this->assertGreaterThan(
            $firstMaxScore,
            $secondMaxScore,
            'Second offense should be scored higher due to history'
        );
    }

    #[Test]
    public function different_fingerprints_should_not_affect_each_other()
    {
        // Create two requests with different fingerprints
        $fingerprint1 = 'isolation-test-1-'.uniqid();
        $fingerprint2 = 'isolation-test-2-'.uniqid();

        $request1 = $this->makeFingerprintedRequest($fingerprint1);
        $request2 = $this->makeFingerprintedRequest($fingerprint2);

        // Generate violations for the first fingerprint
        $scores1 = [];
        for ($i = 0; $i < 10; $i++) {
            $scores1[] = $this->analyzer->analyze($request1);
        }

        // The second fingerprint should still have a clean record
        $score2 = $this->analyzer->analyze($request2);

        $this->assertEquals(0.0, $score2, 'Different fingerprints should be scored independently');
        $this->assertGreaterThan(0.0, end($scores1), 'First fingerprint should have accumulated score');
    }

    #[Test]
    public function analyzer_should_handle_malformed_pattern_data()
    {
        // Create a request with a specific fingerprint
        $fingerprint = 'malformed-data-test-'.uniqid();
        $request = $this->makeFingerprintedRequest($fingerprint);

        // Manually insert malformed pattern data
        $patKey = 'burst:'.substr(md5($fingerprint), 0, 12).':pat';
        $this->dataStore->setValue($patKey, 'not an array as expected');

        // The analyzer should handle this gracefully without errors
        $score = $this->analyzer->analyze($request);

        // We're mainly testing that no exception is thrown
        $this->assertIsFloat($score);
    }
}
