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
        
        $this->dataStore = Mockery::mock(DataStore::class);
        $this->analyzer = new BurstinessAnalyzer($this->dataStore);
        $this->request = Mockery::mock(Request::class);
        $this->request->shouldReceive('getFingerprint')->andReturn('test-fingerprint');
        $this->configureTestEnvironment();
    }
    
    protected function configureTestEnvironment(): void
    {
        Config::set('citadel.burstiness.enable_burstiness_analyzer', true);
        Config::set('citadel.cache.burst_analysis_ttl', 3600);
        Config::set('citadel.burstiness.window_size', 60000);
        Config::set('citadel.burstiness.min_interval', 5000);
        Config::set('citadel.burstiness.max_requests_per_window', 5);
        Config::set('citadel.burstiness.excess_request_score', 10.0);
        Config::set('citadel.burstiness.burst_penalty_score', 20.0);
        Config::set('citadel.burstiness.max_frequency_score', 100.0);
        Config::set('citadel.burstiness.very_regular_threshold', 0.1);
        Config::set('citadel.burstiness.somewhat_regular_threshold', 0.25);
        Config::set('citadel.burstiness.very_regular_score', 30.0);
        Config::set('citadel.burstiness.somewhat_regular_score', 15.0);
        Config::set('citadel.burstiness.pattern_history_size', 5);
        Config::set('citadel.burstiness.history_ttl_multiplier', 6);
        Config::set('citadel.burstiness.min_violations_for_penalty', 1);
        Config::set('citadel.burstiness.max_violation_score', 50.0);
        Config::set('citadel.burstiness.severe_excess_threshold', 10);
        Config::set('citadel.burstiness.max_excess_score', 30.0);
        Config::set('citadel.burstiness.excess_multiplier', 2.0);
        Config::set('citadel.burstiness.ttl_buffer_multiplier', 2);
        Config::set('citadel.burstiness.min_samples_for_pattern', 3);
    }

    #[Test]
    public function it_returns_zero_when_disabled()
    {
        Config::set(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', false);
        
        // Mock cache check
        $this->dataStore->shouldReceive('getValue')
            ->once()
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(0.0, $score);
    }

    #[Test]
    public function it_caps_score_at_max_frequency_score()
    {
        $now = time() * 1000;
        
        $this->dataStore->shouldReceive('getValue')
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        $this->dataStore->shouldReceive('pipeline')
            ->andReturn([null, null, null, 30, []]);
        
        // Allow multiple setValue calls for different components
        $this->dataStore->shouldReceive('setValue')->atLeast()->once();
        
        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(100.0, $score);
    }

    #[Test] 
    public function it_detects_regular_patterns_suggesting_automation()
    {
        $now = time() * 1000;
        $interval = 15000;
        $timestamps = [
            $now - ($interval * 4),
            $now - ($interval * 3),
            $now - ($interval * 2),
            $now - $interval,
            $now
        ];

        $this->dataStore->shouldReceive('getValue')
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        $this->dataStore->shouldReceive('pipeline')
            ->andReturn([null, null, null, 5, $timestamps]);
        
        // Use pattern matching for Redis keys
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::pattern('/hist/'))
            ->andReturn(null);
        
        $this->dataStore->shouldReceive('setValue')->atLeast()->once();
        
        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(30.0, $score);
    }

    #[Test]
    public function it_applies_historical_penalties_for_repeat_offenders()
    {
        $now = time() * 1000;
        $historyData = [
            'violation_count' => 5,
            'max_excess' => 15,
            'last_violation' => $now - 600000
        ];

        $this->dataStore->shouldReceive('getValue')
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        $this->dataStore->shouldReceive('pipeline')
            ->andReturn([null, null, null, 5, []]);
        
        $this->dataStore->shouldReceive('getValue')
            ->with(Mockery::pattern('/hist/'))
            ->andReturn($historyData);
        
        $this->dataStore->shouldReceive('setValue')->atLeast()->once();
        
        $score = $this->analyzer->analyze($this->request);
        $this->assertGreaterThan(40.0, $score);
    }

    #[Test]
    public function it_analyzes_normal_request_pattern_with_no_penalties()
    {
        $now = time() * 1000;
        $this->dataStore->shouldReceive('getValue')
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        $this->dataStore->shouldReceive('pipeline')
            ->andReturn([null, null, null, 3, []]);
        
        $this->dataStore->shouldReceive('setValue')->once();
        
        $score = $this->analyzer->analyze($this->request);
        $this->assertEquals(0.0, $score);
    }

    #[Test]
    public function it_correctly_calculates_ttl_from_window_size()
    {
        $this->dataStore->shouldReceive('getValue')
            ->with('burstiness:test-fingerprint')
            ->andReturn(null);
        
        $this->dataStore->shouldReceive('pipeline')
            ->with(Mockery::on(function ($callback) {
                $pipe = Mockery::mock('stdClass');
                $pipe->shouldReceive('zremrangebyscore')->once();
                $pipe->shouldReceive('zadd')->once();
                $pipe->shouldReceive('expire')->with(Mockery::any(), 120)->once();
                $pipe->shouldReceive('zcard')->once();
                $pipe->shouldReceive('zrange')->once();
                $callback($pipe);
                return true;
            }));
        
        $this->dataStore->shouldReceive('setValue')->once();
        
        $this->analyzer->analyze($this->request);
    }
}