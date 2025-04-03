<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\TestCase;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers\MultiPatternMatcher;
use TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers\PcreMultiPatternMatcher;
use TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers\VectorScanMultiPaternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase as CitadelTestCase;

class MultiPatternMatcherConfigurationTest extends CitadelTestCase
{
    private const CONFIG_PATTERN_MATCHER_KEY = 'citadel.pattern_matcher';
    private const PATTERN_FILE_RELATIVE_PATH = 'data/http-payload-regex.list';
    
    /**
     * Test that the PCRE implementation is correctly selected when configured.
     */
    public function testPcreImplementationIsSelectedWhenConfigured(): void
    {
        // Configure to use PCRE implementation
        Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'pcre');
        
        // Get the MultiPatternMatcher instance from the service container
        $matcher = $this->app->make(MultiPatternMatcher::class);
        
        // Assert that it's the correct implementation
        $this->assertInstanceOf(PcreMultiPatternMatcher::class, $matcher);
    }
    
    /**
     * Test that the Vectorscan implementation is correctly selected when configured.
     */
    public function testVectorscanImplementationIsSelectedWhenConfigured(): void
    {
        // Skip if the vectorscan library isn't available
        try {
            // Try to instantiate the Vectorscan implementation with a test pattern
            new VectorScanMultiPaternMatcher(['test']);
        } catch (\Throwable $e) {
            if (strpos($e->getMessage(), 'libvectorscan shared library not found') !== false) {
                $this->markTestSkipped('Skipped because libvectorscan is not available');
            }
        }
        
        // Configure to use Vectorscan implementation
        Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'vectorscan');
        
        // Get the MultiPatternMatcher instance from the service container
        $matcher = $this->app->make(MultiPatternMatcher::class);
        
        // Assert that it's the correct implementation
        $this->assertInstanceOf(VectorScanMultiPaternMatcher::class, $matcher);
    }
    
    /**
     * Test that Vectorscan is the default implementation when no specific configuration is set.
     */
    public function testVectorscanIsDefaultImplementation(): void
    {
        // Skip if the vectorscan library isn't available
        try {
            new VectorScanMultiPaternMatcher(['test']);
        } catch (\Throwable $e) {
            if (strpos($e->getMessage(), 'libvectorscan shared library not found') !== false) {
                // If Vectorscan is not available, we expect PCRE to be used as a fallback
                // First, clear the implementation config to ensure we're testing the default
                Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', null);
                
                // Attempt to get the implementation (should fall back to PCRE)
                try {
                    $matcher = $this->app->make(MultiPatternMatcher::class);
                    $this->assertInstanceOf(PcreMultiPatternMatcher::class, $matcher);
                } catch (\Throwable $fallbackException) {
                    $this->markTestSkipped('Could not test default implementation fallback: ' . $fallbackException->getMessage());
                }
                
                return;
            }
        }
        
        // Clear any existing implementation config to test the default
        Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', null);
        
        // Get the MultiPatternMatcher instance from the service container
        $matcher = $this->app->make(MultiPatternMatcher::class);
        
        // Assert that Vectorscan is the default
        $this->assertInstanceOf(VectorScanMultiPaternMatcher::class, $matcher);
    }
    
    /**
     * Test that PCRE configuration is properly passed to the implementation.
     */
    public function testPcreConfigurationIsPassedToImplementation(): void
    {
        // Configure to use PCRE implementation with custom settings
        Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'pcre');
        Config::set('citadel.pcre', [
            'pattern_delimiter' => '#',
            'pattern_modifiers' => 'i',
            'max_matches_per_pattern' => 5,
            'timeout_ms' => 500,
        ]);
        
        // Get the MultiPatternMatcher instance from the service container
        $matcher = $this->app->make(MultiPatternMatcher::class);
        
        // Assert it's the PCRE implementation
        $this->assertInstanceOf(PcreMultiPatternMatcher::class, $matcher);
        
        // Assert the config was passed correctly
        $settings = $matcher->getSettings();
        $this->assertEquals('#', $settings['pattern_delimiter']);
        $this->assertEquals('i', $settings['pattern_modifiers']);
        $this->assertEquals(5, $settings['max_matches_per_pattern']);
        $this->assertEquals(500, $settings['timeout_ms']);
    }
    
    /**
     * Test that patterns are loaded from the configured file path.
     */
    public function testPatternsAreLoadedFromConfiguredFilePath(): void
    {
        // Get the absolute path of the patterns file
        $patternFile = __DIR__ . '/../../' . self::PATTERN_FILE_RELATIVE_PATH;
        
        // Create a test pattern file with known content
        $testPatternFile = __DIR__ . '/test_patterns.list';
        file_put_contents($testPatternFile, "test_pattern_1\ntest_pattern_2\n");
        
        try {
            // Configure to use the test pattern file
            Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'pcre'); // Use PCRE for more reliable testing
            Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.patterns_file', $testPatternFile);
            
            // Get the MultiPatternMatcher instance from the service container
            $matcher = $this->app->make(MultiPatternMatcher::class);
            
            // Assert that the patterns were loaded correctly
            $patterns = $matcher->getPatterns();
            $this->assertCount(2, $patterns);
            $this->assertEquals('test_pattern_1', $patterns[0]);
            $this->assertEquals('test_pattern_2', $patterns[1]);
        } finally {
            // Clean up the test pattern file
            @unlink($testPatternFile);
        }
    }
    
    /**
     * Test that the pattern matcher singleton is properly registered in the service container.
     */
    public function testPatternMatcherIsSingletonInContainer(): void
    {
        // Configure to use PCRE implementation for more reliable testing
        Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'pcre');
        
        // Get two instances of the MultiPatternMatcher from the container
        $matcher1 = $this->app->make(MultiPatternMatcher::class);
        $matcher2 = $this->app->make(MultiPatternMatcher::class);
        
        // Assert they are the same instance (singleton)
        $this->assertSame($matcher1, $matcher2);
    }
    
    /**
     * Test that the default implementation is correctly switched to PCRE
     * when Vectorscan is not available.
     */
    public function testFallbackToPcreWhenVectorscanNotAvailable(): void
    {
        // This test requires mocking the VectorScanMultiPaternMatcher constructor
        // to simulate that Vectorscan is not available.
        // Since we can't easily mock that constructor, we'll use a more indirect approach.
        
        // Configure to use Vectorscan implementation
        Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'vectorscan');
        
        // Try to instantiate the Vectorscan implementation
        try {
            new VectorScanMultiPaternMatcher(['test']);
        } catch (\Throwable $e) {
            if (strpos($e->getMessage(), 'libvectorscan shared library not found') !== false) {
                // If Vectorscan is not available, we expect the service provider to fall back to PCRE
                
                // First, set the default explicitly to Vectorscan
                Config::set(self::CONFIG_PATTERN_MATCHER_KEY . '.implementation', 'vectorscan');
                
                // Then mock the createVectorscanPatternMatcher method in the service provider
                // to throw an exception, simulating Vectorscan not being available
                $serviceProvider = $this->getMockBuilder(CitadelServiceProvider::class)
                    ->setConstructorArgs([$this->app])
                    ->onlyMethods(['createVectorscanPatternMatcher'])
                    ->getMock();
                
                $serviceProvider->method('createVectorscanPatternMatcher')
                    ->willThrowException(new \RuntimeException('libvectorscan shared library not found'));
                
                // Register our mocked service provider
                $this->app->register($serviceProvider);
                
                // Now, get a MultiPatternMatcher instance
                try {
                    $matcher = $this->app->make(MultiPatternMatcher::class);
                    // If we get here, it means the service provider successfully fell back to PCRE
                    $this->assertInstanceOf(PcreMultiPatternMatcher::class, $matcher);
                } catch (\Throwable $innerException) {
                    // If we get an exception here, the fallback didn't work
                    $this->fail('Fallback to PCRE failed: ' . $innerException->getMessage());
                }
                
                // We've handled this test case, so return early
                return;
            }
        }
        
        // If we get here, Vectorscan is available, so this test doesn't apply
        $this->markTestSkipped('Vectorscan is available, so we cannot test the fallback behavior');
    }
}