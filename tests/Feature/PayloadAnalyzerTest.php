<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\PayloadAnalyzer;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class PayloadAnalyzerTest extends TestCase
{
    #[Test]
    public function it_detects_sql_injection_patterns()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new PayloadAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'SELECT * FROM users']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected PayloadAnalyzer to detect SQL injection patterns.');
    }

    #[Test]
    public function it_scores_high_entropy_payloads()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new PayloadAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'aGVsbG8gd29ybGQ=']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected PayloadAnalyzer to score high-entropy payloads.');
    }

    #[Test]
    public function it_caches_analysis_results()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new PayloadAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'normal text']);

        $score1 = $analyzer->analyze($request);
        $score2 = $analyzer->analyze($request);

        $this->assertEquals($score1, $score2, 'Expected PayloadAnalyzer to cache analysis results.');
    }
}