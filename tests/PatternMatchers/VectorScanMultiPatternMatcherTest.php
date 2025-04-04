<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use FFI;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class VectorScanMultiPatternMatcherTest extends TestCase
{
    
    public function testScanFindsSingleMatchPerPattern(): void
    {
        $patterns = ['test\d+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        $inputData = 'test123 and then test456 and finally test789';
        $matches = $matcher->scan($inputData);
        
        // With SINGLEMATCH flag, we should only get one match per pattern
        $this->assertCount(1, $matches);
        
        // The match should be the first occurrence of test\d+
        $this->assertSame(0, $matches[0]->from);
        $this->assertSame(5, $matches[0]->to); // Vectorscan is matching 'test1'
        $this->assertSame('test1', $matches[0]->matchedSubstring);
    }
    

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
