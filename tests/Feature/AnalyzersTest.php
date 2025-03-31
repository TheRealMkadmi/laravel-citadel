<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\PayloadAnalyzer;
use TheRealMkadmi\Citadel\Analyzers\DeviceAnalyzer;
use TheRealMkadmi\Citadel\Analyzers\IpAnalyzer;
use TheRealMkadmi\Citadel\Analyzers\SpamminessAnalyzer;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class AnalyzersTest extends TestCase
{
    #[Test]
    public function payload_analyzer_detects_suspicious_patterns()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new PayloadAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'SELECT * FROM users']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected PayloadAnalyzer to detect SQL injection pattern.');
    }

    #[Test]
    public function device_analyzer_scores_bot_user_agents()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new DeviceAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'Googlebot']);

        $score = $analyzer->analyze($request);

        $this->assertEquals(100.0, $score, 'Expected DeviceAnalyzer to score bot user agents highly.');
    }

    #[Test]
    public function ip_analyzer_scores_high_risk_ips()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new IpAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '192.168.1.1']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected IpAnalyzer to score high-risk IPs.');
    }

    #[Test]
    public function spamminess_analyzer_detects_gibberish_text()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new SpamminessAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'asdfghjklqwertyuiopzxcvbnm']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected SpamminessAnalyzer to detect gibberish text.');
    }
}