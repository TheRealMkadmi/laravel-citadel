<?php

namespace TheRealMkadmi\Citadel\Tests\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\BurstinessAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class BurstinessAnalyzerTest extends \TheRealMkadmi\Citadel\Tests\TestCase
{
    protected $dataStore;
    protected $analyzer;
    protected $request;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Mock the DataStore for testing
        $this->dataStore = Mockery::mock(DataStore::class);
        
        // Create the analyzer with the mocked DataStore
        $this->analyzer = new BurstinessAnalyzer($this->dataStore);
        
        // Mock a request with a fingerprint
        $this->request = Mockery::mock(Request::class);
        $this->request->shouldReceive('getFingerprint')->andReturn('test-fingerprint');
        
        // Configure test environment
        $this->configureTestEnvironment();
    }
    
    protected function configureTestEnvironment(): void
    {
        // Set up test configuration values
        Config::set(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', true);
        Config::set(CitadelConfig::KEY_CACHE . '.burst_analysis_ttl', 3600);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.window_size', 60000); // 60 seconds in ms
        Config::set(CitadelConfig::KEY_BURSTINESS . '.min_interval', 5000); // 5 seconds in ms
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_requests_per_window', 5);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.excess_request_score', 10.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.burst_penalty_score', 20.0);
        Config::set(CitadelConfig::KEY_BURSTINESS . '.max_frequency_score', 100.0);
        Config::set('citadel.burstiness.very_regular_threshold', 0.1);
        Config::set('citadel.burstiness.somewhat_regular_threshold', 0.25);
        Config::set('citadel.burstiness.very_regular_score', 30.0);
        Config::set('citadel.burstiness.somewhat_regular_score', 15.0);
        Config::set('citadel.burstiness.pattern_multiplier', 5.0);
        Config::set('citadel.burstiness.max_pattern_score', 20.0);
        Config::set('citadel.burstiness.min_samples_for_pattern', 3);
        Config::set('citadel.burstiness.pattern_history_size', 5);
        Config::set('citadel.burstiness.history_ttl_multiplier', 6);
        Config::set('citadel.burstiness.min_violations_for_penalty', 1);
        Config::set('citadel.burstiness.max_violation_score', 50.0);
        Config::set('citadel.burstiness.severe_excess_threshold', 10);
        Config::set('citadel.burstiness.max_excess_score', 30.0);
        Config::set('citadel.burstiness.excess_multiplier', 2.0);
        Config::set('citadel.burstiness.ttl_buffer_multiplier', 2);
    }
    
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
    
    #[Test]
    public function it_returns_zero_when_disabled()
    {
        Config::set(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', false);
        
        $score = $this->analyzer->analyze($this->request);
        
        $this->assertEquals(0.0, $score);
    }
    
    #[Test]
    public function it_returns_zero_when_no_fingerprint()
    {
        $request = Mockery::mock(Request::class);
        $request->shouldReceive('getFingerprint')->andReturn(null);
        
        $score = $this->analyzer->analyze($request);
        
        $this->assertEquals(0.0, $score);
    }
    
    #[Test]
    public function it_returns_cached_score_if_available()
    {
        // Setup cache hit scenario
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(42.0);
            
        $score = $this->analyzer->analyze($this->request);
        
        $this->assertEquals(42.0, $score);
    }
    
    #[Test]
    public function it_analyzes_normal_request_pattern_with_no_penalties()
    {
        // Timestamp sequence with normal intervals
        $now = time() * 1000; // Current time in ms
        
        // Configure cache miss
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup pipeline
        $this->setupPipelineForNormalCase($now);
        
        // No history data
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn(null);
        
        // Expect final score to be saved to cache
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', 0.0, Mockery::any())
            ->once();
        
        $score = $this->analyzer->analyze($this->request);
        
        $this->assertEquals(0.0, $score);
    }
    
    #[Test]
    public function it_detects_excessive_requests_and_applies_penalty()
    {
        $now = time() * 1000;
        
        // Configure cache miss
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup pipeline with excessive requests (10 instead of allowed 5)
        $this->dataStore->shouldReceive('pipeline')
            ->once()
            ->andReturnUsing(function ($callback) use ($now) {
                $pipe = Mockery::mock('stdClass');
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                $pipe->shouldReceive('expire')->once();
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                
                $callback($pipe);
                
                // Return 10 requests (excessive compared to 5 max)
                return [null, null, null, 10, [$now - 55000, $now - 45000, $now - 30000, $now - 15000, $now]];
            });
        
        // Setup history tracking
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn(null);
        
        // Expect history to be stored
        $this->dataStore->shouldReceive('setValue')
            ->with(Mockery::containsString('hist'), Mockery::any(), Mockery::any())
            ->once();
        
        // Check for pattern analysis
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('pat'))
            ->andReturn(null);
        
        // Expect pattern data to be stored
        $this->dataStore->shouldReceive('setValue')
            ->with(Mockery::containsString('pat'), Mockery::any(), Mockery::any())
            ->once();
        
        // Expect final score to be saved to cache
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', Mockery::any(), Mockery::any())
            ->once();
        
        $score = $this->analyzer->analyze($this->request);
        
        // Expect excess request penalty: 5 excess * 10 points (using sqrt formula)
        $this->assertGreaterThan(0, $score);
    }
    
    #[Test]
    public function it_detects_burst_patterns_and_applies_penalty()
    {
        $now = time() * 1000;
        
        // Configure cache miss
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup pipeline with burst pattern (requests too close together)
        $timestamps = [
            $now - 30000,
            $now - 28000, // Less than 5000ms from next one (burst)
            $now - 26000, // Less than 5000ms from next one (burst)
            $now - 15000,
            $now
        ];
        
        $this->dataStore->shouldReceive('pipeline')
            ->once()
            ->andReturnUsing(function ($callback) use ($timestamps, $now) {
                $pipe = Mockery::mock('stdClass');
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                $pipe->shouldReceive('expire')->once();
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                
                $callback($pipe);
                
                // Return 5 requests (not excessive) but with burst pattern
                return [null, null, null, 5, $timestamps];
            });
        
        // No history data
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn(null);
            
        // Check for pattern analysis
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('pat'))
            ->andReturn(null);
        
        // Expect pattern data to be stored
        $this->dataStore->shouldReceive('setValue')
            ->with(Mockery::containsString('pat'), Mockery::any(), Mockery::any())
            ->once();
        
        // Expect final score to be saved to cache
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', Mockery::any(), Mockery::any())
            ->once();
        
        $score = $this->analyzer->analyze($this->request);
        
        // Expect burst penalty to be applied (20 points by default)
        $this->assertEquals(20.0, $score);
    }
    
    #[Test]
    public function it_detects_regular_patterns_suggesting_automation()
    {
        $now = time() * 1000;
        
        // Configure cache miss
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup pipeline with very regular request pattern (same interval)
        $interval = 15000; // Exactly 15 seconds between each request
        $timestamps = [
            $now - ($interval * 4),
            $now - ($interval * 3),
            $now - ($interval * 2),
            $now - $interval,
            $now
        ];
        
        $this->dataStore->shouldReceive('pipeline')
            ->once()
            ->andReturnUsing(function ($callback) use ($timestamps, $now) {
                $pipe = Mockery::mock('stdClass');
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                $pipe->shouldReceive('expire')->once();
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                
                $callback($pipe);
                
                // Return 5 requests with perfectly regular timing
                return [null, null, null, 5, $timestamps];
            });
        
        // No history data
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn(null);
            
        // Check for pattern analysis
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('pat'))
            ->andReturn(null);
        
        // Expect pattern data to be stored
        $this->dataStore->shouldReceive('setValue')
            ->with(Mockery::containsString('pat'), Mockery::any(), Mockery::any())
            ->once();
        
        // Expect final score to be saved to cache
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', Mockery::any(), Mockery::any())
            ->once();
        
        $score = $this->analyzer->analyze($this->request);
        
        // Expect pattern penalty to be applied (30 points by default for very regular patterns)
        $this->assertEquals(30.0, $score);
    }
    
    #[Test]
    public function it_applies_historical_penalties_for_repeat_offenders()
    {
        $now = time() * 1000;
        
        // Configure cache miss
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup pipeline with normal request pattern
        $this->setupPipelineForNormalCase($now);
        
        // Setup historical data showing this is a repeat offender
        $historyData = [
            'first_violation' => $now - 3600000, // 1 hour ago
            'last_violation' => $now - 600000, // 10 minutes ago
            'violation_count' => 5,
            'max_excess' => 15, // Severe excess
            'total_excess' => 35,
        ];
        
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn($historyData);
        
        // Expect pattern check but no pattern found
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('pat'))
            ->andReturn(null);
        
        // Expect pattern data to be stored
        $this->dataStore->shouldReceive('setValue')
            ->with(Mockery::containsString('pat'), Mockery::any(), Mockery::any())
            ->once();
        
        // Expect final score to be saved to cache
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', Mockery::any(), Mockery::any())
            ->once();
        
        $score = $this->analyzer->analyze($this->request);
        
        // Expect historical penalties: violation_count penalty + severe excess penalty
        // History score should be significant
        $this->assertGreaterThan(40.0, $score);
    }
    
    #[Test]
    public function it_caps_score_at_max_frequency_score()
    {
        $now = time() * 1000;
        
        // Configure cache miss
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup pipeline with extremely excessive requests (30 instead of allowed 5)
        $this->dataStore->shouldReceive('pipeline')
            ->once()
            ->andReturnUsing(function ($callback) use ($now) {
                $pipe = Mockery::mock('stdClass');
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                $pipe->shouldReceive('expire')->once();
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                
                $callback($pipe);
                
                // Return 30 requests (very excessive compared to 5 max)
                return [null, null, null, 30, []];
            });
        
        // Setup history tracking
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn(null);
        
        // Expect history to be stored
        $this->dataStore->shouldReceive('setValue')
            ->with(Mockery::containsString('hist'), Mockery::any(), Mockery::any())
            ->once();
        
        // Expect final score to be saved to cache
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', Mockery::any(), Mockery::any())
            ->once();
        
        $score = $this->analyzer->analyze($this->request);
        
        // Score should be capped at max_frequency_score (100.0)
        $this->assertEquals(100.0, $score);
    }
    
    /**
     * Helper method to setup a pipeline for cases with normal request patterns
     */
    private function setupPipelineForNormalCase(int $now): void
    {
        $this->dataStore->shouldReceive('pipeline')
            ->once()
            ->andReturnUsing(function ($callback) use ($now) {
                $pipe = Mockery::mock('stdClass');
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                $pipe->shouldReceive('expire')->once();
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                
                $callback($pipe);
                
                // Return 5 requests (max allowed) with normal intervals
                return [
                    null, 
                    null, 
                    null, 
                    5, 
                    [
                        $now - 50000, // 50 seconds ago
                        $now - 40000, // 40 seconds ago
                        $now - 30000, // 30 seconds ago
                        $now - 15000, // 15 seconds ago
                        $now          // now
                    ]
                ];
            });
    }
    
    #[Test]
    public function it_correctly_calculates_ttl_from_window_size()
    {
        // Configure cache miss to force analyzer to calculate TTL
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        // Setup minimal pipeline that uses calculateTTL internally
        $this->dataStore->shouldReceive('pipeline')
            ->once()
            ->andReturnUsing(function ($callback) {
                $pipe = Mockery::mock('stdClass');
                
                // These are the key calls we want to verify
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                
                // We specifically want to capture the expire call to check the TTL
                $pipe->shouldReceive('expire')
                    ->withArgs(function ($key, $ttl) {
                        // With window size of 60000ms and multiplier of 2, TTL should be 120 seconds
                        $this->assertEquals(120, $ttl);
                        return true;
                    })
                    ->once();
                    
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                
                $callback($pipe);
                
                return [null, null, null, 1, []];
            });
        
        // Other necessary mocks to complete the analyze call
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::containsString('hist'))
            ->andReturn(null);
            
        $this->dataStore->shouldReceive('setValue')
            ->with('burstiness:test-fingerprint', Mockery::any(), Mockery::any())
            ->once();
        
        // Call analyze to trigger TTL calculation
        $this->analyzer->analyze($this->request);
    }
}