<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use PHPUnit\Framework\TestCase;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatch;
use TheRealMkadmi\Citadel\PatternMatchers\PcreMultiPatternMatcher;

class PcreMultiPatternMatcherTest extends TestCase
{
    /**
     * Test that the constructor correctly initializes the patterns
     */
    public function testConstructorInitializesPatterns(): void
    {
        $patterns = ['foo\w+', 'bar\d+', 'baz\s+'];
        $matcher = new PcreMultiPatternMatcher($patterns);

        $this->assertIsArray($matcher->getPatterns());
        $this->assertEquals($patterns, $matcher->getPatterns());
    }

    /**
     * Test that invalid patterns throw exceptions
     */
    public function testInvalidPatternsThrowException(): void
    {
        $patterns = ['valid\w+', '(invalid['];
        
        // Tell PHPUnit to expect the RuntimeException but ignore PHP warnings
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid PCRE pattern');
        
        // Temporarily disable warning output for this test
        $errorLevel = error_reporting();
        error_reporting($errorLevel & ~E_WARNING);
        
        try {
            new PcreMultiPatternMatcher($patterns);
        } finally {
            // Restore original error reporting level
            error_reporting($errorLevel);
        }
    }

    /**
     * Test scan with no matches
     */
    public function testScanWithNoMatches(): void
    {
        $patterns = ['foo\d+', 'bar\d+'];
        $matcher = new PcreMultiPatternMatcher($patterns);
        
        $content = 'This string contains no matches';
        $matches = $matcher->scan($content);
        
        $this->assertIsArray($matches);
        $this->assertEmpty($matches);
    }

    /**
     * Test scan with single pattern match
     */
    public function testScanWithSingleMatch(): void
    {
        $patterns = ['foo\d+', 'bar\d+'];
        $matcher = new PcreMultiPatternMatcher($patterns);
        
        $content = 'This string contains foo123';
        $matches = $matcher->scan($content);
        
        $this->assertIsArray($matches);
        $this->assertCount(1, $matches);
        
        $match = $matches[0];
        $this->assertInstanceOf(MultiPatternMatch::class, $match);
        $this->assertEquals(0, $match->id);
        $this->assertEquals('foo123', $match->matchedSubstring);
        $this->assertEquals($patterns[0], $match->originalPattern);
        $this->assertEquals(20, $match->from);
        $this->assertEquals(26, $match->to);
    }
    
    /**
     * Test scan with multiple pattern matches
     */
    public function testScanWithMultipleMatches(): void
    {
        $patterns = ['foo\d+', 'bar\d+'];
        $matcher = new PcreMultiPatternMatcher($patterns);
        
        $content = 'This contains foo123 and also bar456';
        $matches = $matcher->scan($content);
        
        $this->assertIsArray($matches);
        $this->assertCount(2, $matches);
        
        // First match should be foo123
        $firstMatch = $matches[0];
        $this->assertEquals(0, $firstMatch->id);
        $this->assertEquals('foo123', $firstMatch->matchedSubstring);
        
        // Second match should be bar456
        $secondMatch = $matches[1];
        $this->assertEquals(1, $secondMatch->id);
        $this->assertEquals('bar456', $secondMatch->matchedSubstring);
        
        // Ensure matches are ordered by position
        $this->assertLessThan($secondMatch->from, $firstMatch->from);
    }

    /**
     * Test scan with overlapping matches
     */
    public function testScanWithOverlappingMatches(): void
    {
        $patterns = ['foo\w+', 'oo\w+'];
        $matcher = new PcreMultiPatternMatcher($patterns);
        
        $content = 'This contains foobar';
        $matches = $matcher->scan($content);
        
        $this->assertIsArray($matches);
        $this->assertCount(2, $matches);
        
        // Matches should be sorted by position
        $this->assertEquals('foobar', $matches[0]->matchedSubstring);
        $this->assertEquals('oobar', $matches[1]->matchedSubstring);
    }

    /**
     * Test that options are correctly passed to the matcher
     */
    public function testOptionsAreRespected(): void
    {
        $patterns = ['FOO\d+', 'BAR\d+'];
        $options = [
            'pattern_modifiers' => '', // No 'i' flag means case-sensitive
        ];
        
        $matcher = new PcreMultiPatternMatcher($patterns, $options);
        
        // This shouldn't match because our patterns are uppercase and we're using case-sensitive mode
        $content = 'This contains foo123 and bar456';
        $matches = $matcher->scan($content);
        
        $this->assertEmpty($matches);
        
        // This should match because the content has uppercase patterns
        $content = 'This contains FOO123 and BAR456';
        $matches = $matcher->scan($content);
        
        $this->assertCount(2, $matches);
    }
    
    /**
     * Test limit on maximum matches per pattern
     */
    public function testMaxMatchesPerPattern(): void
    {
        $patterns = ['a\w'];
        $options = [
            'max_matches_per_pattern' => 3,
        ];
        
        $matcher = new PcreMultiPatternMatcher($patterns, $options);
        
        $content = 'ax ay az aa ab ac ad ae af';
        $matches = $matcher->scan($content);
        
        // Should only capture the first 3 matches (ax, ay, az)
        $this->assertCount(3, $matches);
        $this->assertEquals('ax', $matches[0]->matchedSubstring);
        $this->assertEquals('ay', $matches[1]->matchedSubstring);
        $this->assertEquals('az', $matches[2]->matchedSubstring);
    }
    
    /**
     * Test updating matcher settings
     */
    public function testUpdateSettings(): void
    {
        $patterns = ['foo\d+', 'bar\d+'];
        $matcher = new PcreMultiPatternMatcher($patterns);
        
        // Default settings should include case-insensitive flag
        $content = 'This contains FOO123';
        $matches = $matcher->scan($content);
        $this->assertCount(1, $matches);
        
        // Update settings to use case-sensitive matching
        $matcher->updateSettings(['pattern_modifiers' => '']);
        
        // Now uppercase shouldn't match
        $matches = $matcher->scan($content);
        $this->assertEmpty($matches);
    }

    /**
     * Test getting settings
     */
    public function testGetSettings(): void
    {
        $patterns = ['foo\d+'];
        $options = [
            'pattern_delimiter' => '#',
            'pattern_modifiers' => 'i',
            'custom_option' => 'value',
        ];
        
        $matcher = new PcreMultiPatternMatcher($patterns, $options);
        
        $settings = $matcher->getSettings();
        
        $this->assertEquals('#', $settings['pattern_delimiter']);
        $this->assertEquals('i', $settings['pattern_modifiers']);
        $this->assertEquals('value', $settings['custom_option']);
    }

    /**
     * Test destructor restores the backtrack limit
     */
    public function testDestructorRestoresBacktrackLimit(): void
    {
        $originalLimit = ini_get('pcre.backtrack_limit');
        
        $patterns = ['foo\d+'];
        $matcher = new PcreMultiPatternMatcher($patterns);
        
        // Force garbage collection to trigger the destructor
        unset($matcher);
        
        // The backtrack limit should be restored
        $this->assertEquals($originalLimit, ini_get('pcre.backtrack_limit'));
    }
}