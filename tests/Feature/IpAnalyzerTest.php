<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\IpAnalyzer;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class IpAnalyzerTest extends TestCase
{
    #[Test]
    public function it_scores_high_risk_ip_correctly()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new IpAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '192.168.1.1']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected IpAnalyzer to score high-risk IPs.');
    }

    #[Test]
    public function it_returns_zero_for_private_ip()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new IpAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);

        $score = $analyzer->analyze($request);

        $this->assertEquals(0, $score, 'Expected IpAnalyzer to return zero for private IPs.');
    }

    #[Test]
    public function it_caches_ip_analysis_results()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new IpAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);

        $score1 = $analyzer->analyze($request);
        $score2 = $analyzer->analyze($request);

        $this->assertEquals($score1, $score2, 'Expected IpAnalyzer to cache analysis results.');
    }
}