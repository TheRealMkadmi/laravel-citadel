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
}