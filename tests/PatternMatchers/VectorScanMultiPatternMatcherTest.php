<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatch;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase; 

class VectorScanMultiPatternMatcherTest extends TestCase
{
    /**
     * Skip all tests if libvectorscan isn't available
     */
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        
        // Try to load the vectorscan library - if it fails, skip all tests in this class
        try {
            new VectorScanMultiPatternMatcher(['test_pattern']);
        } catch (\RuntimeException $e) {
            self::markTestSkipped('libvectorscan library is not available: ' . $e->getMessage());
        } catch (\Throwable $e) {
            // If we get a different error (like a compilation error), that's fine
            // We just need to make sure the library exists
        }
    }
    
    /**
     * Test that the constructor correctly initializes the patterns
     */
    public function testConstructorInitializesPatterns(): void
    {
        $patterns = ['foo\w+', 'bar\d+', 'baz\s+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $this->assertIsArray($matcher->getPatterns());
        $this->assertEquals($patterns, $matcher->getPatterns());
    }
    
    /**
     * Test scan with no matches
     */
    public function testScanWithNoMatches(): void
    {
        $patterns = ['foo\d+', 'bar\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
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
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $content = 'This string contains foo123';
        $matches = $matcher->scan($content);
        
        $this->assertIsArray($matches);
        $this->assertCount(1, $matches);
        
        $match = $matches[0];
        $this->assertInstanceOf(MultiPatternMatch::class, $match);
        $this->assertEquals(0, $match->id);
        $this->assertEquals('foo123', $match->matchedSubstring);
        $this->assertEquals($patterns[0], $match->originalPattern);
    }
    
    /**
     * Test scan with multiple pattern matches
     */
    public function testScanWithMultipleMatches(): void
    {
        $patterns = ['foo\d+', 'bar\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $content = 'This contains foo123 and also bar456';
        $matches = $matcher->scan($content);
        
        $this->assertIsArray($matches);
        $this->assertNotEmpty($matches);
        
        // Find matches for each pattern
        $foundFoo = false;
        $foundBar = false;
        
        foreach ($matches as $match) {
            if ($match->id === 0 && strpos($match->matchedSubstring, 'foo') === 0) {
                $foundFoo = true;
            }
            if ($match->id === 1 && strpos($match->matchedSubstring, 'bar') === 0) {
                $foundBar = true;
            }
        }
        
        $this->assertTrue($foundFoo, 'Did not find match for pattern "foo\d+"');
        $this->assertTrue($foundBar, 'Did not find match for pattern "bar\d+"');
    }
    
    /**
     * Test exception when database or scratch is not initialized
     */
    public function testExceptionWhenNotInitialized(): void
    {
        // Use reflection to create an instance without proper initialization
        $reflectionClass = new \ReflectionClass(VectorScanMultiPatternMatcher::class);
        $matcher = $reflectionClass->newInstanceWithoutConstructor();
        
        // Scan should throw exception because db and scratch are not initialized
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Vectorscan database or scratch space not initialized');
        $matcher->scan('some content');
    }
    
    /**
     * Test invalid pattern compilation
     */
    public function testInvalidPatternCompilation(): void
    {
        // This is an invalid regex pattern for the vectorscan library
        $patterns = ['a{-1}'];  // Negative repetition count is invalid
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('libvectorscan compilation failed');
        
        new VectorScanMultiPatternMatcher($patterns);
    }
}