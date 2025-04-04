<?php

namespace TheRealMkadmi\Citadel\Tests\Analyzers;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\PayloadAnalyzer;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatcher;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class PayloadAnalyzerTest extends TestCase
{
    private ArrayDataStore $dataStore;

    private MultiPatternMatcher $matcher;

    private PayloadAnalyzer $analyzer;

    private string $patternsFile = __DIR__.'/../../resources/payload-inspection-patterns.list';

    protected function setUp(): void
    {
        parent::setUp();
        $this->dataStore = new ArrayDataStore;

        $lines = file($this->patternsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

        $this->matcher = new VectorScanMultiPatternMatcher($lines);
        $this->analyzer = new PayloadAnalyzer($this->dataStore, $this->matcher);
    }

    #[Test]
    public function test_rules_are_loaded(): void
    {
        // Ensure the matcher has loaded a non-zero number of patterns.
        $this->assertGreaterThan(0, count($this->matcher->getPatterns()), 'Expected patterns to be loaded from file.');
    }

    #[Test]
    public function test_benign_payload_returns_zero_score(): void
    {
        // Provide a common benign input.
        $request = Request::create('/', 'POST', [], [], [], [], 'This is a normal text without attack vectors.');
        $score = $this->analyzer->analyze($request);
        $this->assertEquals(0.0, $score, 'Benign payload should not trigger any matches.');
    }

    #[Test]
    public function test_sql_injection_payload_returns_positive_score(): void
    {
        // SQL injection payload should produce a positive score.
        $request = Request::create('/', 'POST', [], [], [], [], 'SELECT * FROM users WHERE id=1');
        $score = $this->analyzer->analyze($request);
        $this->assertGreaterThan(0.0, $score, 'SQL injection payload should yield score greater than zero.');
    }
}
