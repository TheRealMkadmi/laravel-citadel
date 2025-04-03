<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatch;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;
use FFI; // Import FFI for type hinting if needed

class VectorScanMultiPatternMatcherTest extends TestCase
{
    /**
     * Test that the FFI object is created successfully with valid patterns.
     * This implicitly tests library loading.
     */
    public function testLibraryLoadsSuccessfully(): void
    {
        $patterns = ['test\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);

        // Use reflection to access the private ffi property
        $reflection = new \ReflectionClass($matcher);
        $ffiProperty = $reflection->getProperty('ffi');
        $ffiProperty->setAccessible(true); // Make private property accessible
        $ffiInstance = $ffiProperty->getValue($matcher);
        $this->assertInstanceOf(FFI::class, $ffiInstance, 'FFI object should be initialized.');
    }

    /**
     * Test that the HS_MODE_BLOCK constant is defined and has the correct value.
     */
    public function testHsModeBlockConstantIsDefinedAndCorrect(): void
    {
        $reflection = new \ReflectionClass(VectorScanMultiPatternMatcher::class);
        $this->assertTrue($reflection->hasConstant('HS_MODE_BLOCK'), 'HS_MODE_BLOCK constant should be defined.');
        // Update the expected value from 0 to 1
        $this->assertSame(1, $reflection->getConstant('HS_MODE_BLOCK'), 'HS_MODE_BLOCK constant should be 1.');
    }

    /**
     * Test that getPatterns() returns the patterns provided in the constructor.
     */
    public function testGetPatternsReturnsCorrectPatterns(): void
    {
        $expectedPatterns = ['test\d+', 'foo\w*', 'bar[a-z]+'];
        $matcher = new VectorScanMultiPatternMatcher($expectedPatterns);
        
        $actualPatterns = $matcher->getPatterns();
        
        $this->assertSame($expectedPatterns, $actualPatterns);
    }

    /**
     * Test that scan() finds a simple match.
     */
    public function testScanFindsSimpleMatch(): void
    {
        $patterns = ['test\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $inputData = 'This is a test123 string';
        $matches = $matcher->scan($inputData);
        
        $this->assertCount(1, $matches);
        $this->assertInstanceOf(MultiPatternMatch::class, $matches[0]);
        $this->assertSame(0, $matches[0]->id);
        $this->assertSame(10, $matches[0]->from); // "test123" starts at position 10
        $this->assertSame(17, $matches[0]->to);   // "test123" ends at position 17
        $this->assertSame('test123', $matches[0]->matchedSubstring);
        $this->assertSame($patterns[0], $matches[0]->originalPattern);
    }

    /**
     * Test that scan() finds multiple occurrences of the same pattern.
     */
    public function testScanFindsMultipleMatches(): void
    {
        $patterns = ['test\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $inputData = 'test123 and then test456 and finally test789';
        $matches = $matcher->scan($inputData);
        
        $this->assertCount(3, $matches);
        
        $expectedMatches = [
            ['from' => 0, 'to' => 7, 'match' => 'test123'],
            ['from' => 17, 'to' => 24, 'match' => 'test456'],
            ['from' => 38, 'to' => 45, 'match' => 'test789']
        ];
        
        foreach ($matches as $index => $match) {
            $this->assertSame($expectedMatches[$index]['from'], $match->from);
            $this->assertSame($expectedMatches[$index]['to'], $match->to);
            $this->assertSame($expectedMatches[$index]['match'], $match->matchedSubstring);
        }
    }

    /**
     * Test that scan() correctly identifies matches from multiple different patterns.
     */
    public function testScanWithMultiplePatterns(): void
    {
        $patterns = ['test\d+', 'foo\w*', 'bar[a-z]+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $inputData = 'test123 and foo and barcode';
        $matches = $matcher->scan($inputData);
        
        // Sort matches by their position in the string for consistent testing
        usort($matches, function($a, $b) {
            return $a->from <=> $b->from;
        });
        
        $this->assertCount(3, $matches);
        
        // First match should be "test123" (pattern 0)
        $this->assertSame(0, $matches[0]->id);
        $this->assertSame('test123', $matches[0]->matchedSubstring);
        
        // Second match should be "foo" (pattern 1)
        $this->assertSame(1, $matches[1]->id);
        $this->assertSame('foo', $matches[1]->matchedSubstring);
        
        // Third match should be "barcode" (pattern 2)
        $this->assertSame(2, $matches[2]->id);
        $this->assertSame('barcode', $matches[2]->matchedSubstring);
    }

    /**
     * Test that scan() returns an empty array when no matches are found.
     */
    public function testScanWithNoMatches(): void
    {
        $patterns = ['test\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $inputData = 'This string has no matches';
        $matches = $matcher->scan($inputData);
        
        $this->assertIsArray($matches);
        $this->assertEmpty($matches);
    }

    /**
     * Test that scan() returns an empty array when input data is empty.
     */
    public function testScanWithEmptyData(): void
    {
        $patterns = ['test\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $matches = $matcher->scan('');
        
        $this->assertIsArray($matches);
        $this->assertEmpty($matches);
    }

    /**
     * Test that constructor throws an exception when given an invalid pattern.
     */
    public function testInvalidPatternThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        
        // This is an invalid regex pattern that should cause compilation to fail
        $patterns = ['test['];
        new VectorScanMultiPatternMatcher($patterns);
    }

    /**
     * Test that scan doesn't work if database is not initialized.
     */
    public function testScanThrowsExceptionIfDatabaseNotInitialized(): void
    {
        // Expect any type of exception that contains the specific message
        $this->expectExceptionMessage("Vectorscan database or scratch space not initialized");
        
        // Create a matcher with reflection to manipulate its internal state
        $matcher = new VectorScanMultiPatternMatcher(['test\d+']);
        
        // Use reflection to set db and scratch to null
        $reflection = new \ReflectionClass($matcher);
        
        $dbProperty = $reflection->getProperty('db');
        $dbProperty->setAccessible(true);
        $dbProperty->setValue($matcher, null);
        
        $scratchProperty = $reflection->getProperty('scratch');
        $scratchProperty->setAccessible(true);
        $scratchProperty->setValue($matcher, null);
        
        $matcher->scan('test data');
    }
}