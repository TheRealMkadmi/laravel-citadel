<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\SpamminessAnalyzer;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class SpamminessAnalyzerTest extends TestCase
{
    #[Test]
    public function it_detects_gibberish_text()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new SpamminessAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'asdfghjklqwertyuiopzxcvbnm']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected SpamminessAnalyzer to detect gibberish text.');
    }

    #[Test]
    public function it_scores_repetitive_content()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new SpamminessAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'spam spam spam spam spam']);

        $score = $analyzer->analyze($request);

        $this->assertGreaterThan(0, $score, 'Expected SpamminessAnalyzer to score repetitive content.');
    }

    #[Test]
    public function it_caches_analysis_results()
    {
        $dataStore = new ArrayDataStore();
        $analyzer = new SpamminessAnalyzer($dataStore);

        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => 'TestAgent']);
        $request->setJson(['key' => 'normal text']);

        $score1 = $analyzer->analyze($request);
        $score2 = $analyzer->analyze($request);

        $this->assertEquals($score1, $score2, 'Expected SpamminessAnalyzer to cache analysis results.');
    }
}