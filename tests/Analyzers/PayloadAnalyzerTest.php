<?php

namespace TheRealMkadmi\Citadel\Tests\Analyzers;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\PayloadAnalyzer;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;

class PayloadAnalyzerTest extends TestCase
{
    private ArrayDataStore $dataStore;
    private MultiPatternMatcher $matcher;
    private PayloadAnalyzer $analyzer;
    private string $patternsFile = __DIR__ . '/../../resources/payload-inspection-patterns.list';

    protected function setUp(): void
    {
        parent::setUp();
        $this->dataStore = new ArrayDataStore;

        $lines = file($this->patternsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $patterns =
            collect($lines)
                ->map(fn($line) => trim($line))
                ->filter(fn($line) => !empty($line) && !str_starts_with($line, '#'))
                ->toArray();

        $this->matcher = new VectorScanMultiPatternMatcher($patterns);
        $this->analyzer = new PayloadAnalyzer($this->dataStore, $this->matcher);
    }

    #[Test]
    public function testRulesAreLoaded(): void
    {
        // Ensure the matcher has loaded a non-zero number of patterns.
        $this->assertGreaterThan(0, count($this->matcher->getPatterns()), 'Expected patterns to be loaded from file.');
    }

    #[Test]
    public function testBenignPayloadReturnsZeroScore(): void
    {
        // Provide a common benign input.
        $request = Request::create('/', 'POST', [], [], [], [], 'This is a normal text without attack vectors.');
        $score = $this->analyzer->analyze($request);
        $this->assertEquals(0.0, $score, 'Benign payload should not trigger any matches.');
    }

    #[Test]
    public function testSqlInjectionPayloadReturnsPositiveScore(): void
    {
        // SQL injection payload should produce a positive score.
        $request = Request::create('/', 'POST', [], [], [], [], 'SELECT * FROM users WHERE id=1');
        $score = $this->analyzer->analyze($request);
        $this->assertGreaterThan(0.0, $score, 'SQL injection payload should yield score greater than zero.');
    }
}
