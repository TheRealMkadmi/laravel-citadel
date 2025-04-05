<?php

namespace TheRealMkadmi\Citadel\Tests\Integration;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatcher;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class HashValidationIntegrationTest extends TestCase
{
    private string $testPatternsFilePath;

    private string $testDbPath;

    private array $testPatterns = ['test\d+', 'example[a-z]+', 'sample\w+'];

    protected function setUp(): void
    {
        parent::setUp();

        // Set up test paths
        $this->testPatternsFilePath = storage_path('app/test/integration_test_patterns.list');
        $this->testDbPath = storage_path('app/test/integration_test_patterns.db');

        // Ensure the test directory exists
        if (! File::isDirectory(dirname($this->testPatternsFilePath))) {
            File::makeDirectory(dirname($this->testPatternsFilePath), 0755, true);
        }

        // Create a test patterns file
        File::put($this->testPatternsFilePath, implode(PHP_EOL, $this->testPatterns));

        // Clean up any existing test database files
        $this->cleanupFiles();
    }

    protected function tearDown(): void
    {
        // Clean up test files
        $this->cleanupFiles();
        parent::tearDown();
    }

    private function cleanupFiles(): void
    {
        if (File::exists($this->testDbPath)) {
            File::delete($this->testDbPath);
        }

        if (File::exists($this->testDbPath.'.hash')) {
            File::delete($this->testDbPath.'.hash');
        }
    }

    /**
     * Check if Vectorscan is available on this system
     */
    private function isVectorscanAvailable(): bool
    {
        try {
            new VectorScanMultiPatternMatcher(['test']);

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Test that the service provider correctly handles hash validation when enabled
     */
    public function test_service_provider_uses_hash_validation_when_enabled(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Configure for hash validation
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.implementation', 'vectorscan');
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.patterns_file', $this->testPatternsFilePath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.serialized_db_path', $this->testDbPath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.auto_serialize', true);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.use_hash_validation', true);

        // Create a fresh service provider instance
        $serviceProvider = new CitadelServiceProvider($this->app);

        // Use reflection to access the private createVectorscanPatternMatcher method
        $reflection = new \ReflectionClass($serviceProvider);
        $method = $reflection->getMethod('createVectorscanPatternMatcher');
        $method->setAccessible(true);

        // Create the matcher through the service provider
        $matcher = $method->invoke($serviceProvider, $this->testPatterns);

        // Verify the database was created with hash
        $this->assertTrue(File::exists($this->testDbPath), 'Database file should be created');
        $this->assertTrue(File::exists($this->testDbPath.'.hash'), 'Hash file should be created');

        // Modify patterns file
        File::put($this->testPatternsFilePath, 'new_pattern\d+'.PHP_EOL.'modified_pattern\w+');

        // First, record the current modification time
        $firstModTime = File::lastModified($this->testDbPath);

        // Create a second matcher - should detect changed patterns and recompile
        $matcher2 = $method->invoke($serviceProvider, ['new_pattern\d+', 'modified_pattern\w+']);

        // Verify the database was recompiled
        $secondModTime = File::lastModified($this->testDbPath);
        $this->assertGreaterThan($firstModTime, $secondModTime, 'Database should be recompiled when patterns change');
    }

    /**
     * Test that hash validation can be disabled
     */
    public function test_hash_validation_can_be_disabled(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Configure without hash validation
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.implementation', 'vectorscan');
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.patterns_file', $this->testPatternsFilePath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.serialized_db_path', $this->testDbPath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.auto_serialize', true);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.use_hash_validation', false);

        // Create a fresh service provider instance
        $serviceProvider = new CitadelServiceProvider($this->app);

        // Use reflection to access the private createVectorscanPatternMatcher method
        $reflection = new \ReflectionClass($serviceProvider);
        $method = $reflection->getMethod('createVectorscanPatternMatcher');
        $method->setAccessible(true);

        // Create the matcher through the service provider
        $matcher = $method->invoke($serviceProvider, $this->testPatterns);

        // Verify the database was created (might have hash or not, depending on implementation)
        $this->assertTrue(File::exists($this->testDbPath), 'Database file should be created');

        // Modify patterns file
        File::put($this->testPatternsFilePath, 'new_pattern\d+'.PHP_EOL.'modified_pattern\w+');

        // First, record the current modification time
        $firstModTime = File::lastModified($this->testDbPath);

        // Create a second matcher - should NOT detect changed patterns when hash validation is disabled
        $matcher2 = $method->invoke($serviceProvider, ['new_pattern\d+', 'modified_pattern\w+']);

        // Verify the database was NOT recompiled (timestamp should be the same)
        $secondModTime = File::lastModified($this->testDbPath);
        $this->assertEquals($firstModTime, $secondModTime, 'Database should not be recompiled when hash validation is disabled');
    }

    /**
     * Test that auto-serialization can be disabled
     */
    public function test_auto_serialization_can_be_disabled(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Configure with hash validation but without auto-serialization
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.implementation', 'vectorscan');
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.patterns_file', $this->testPatternsFilePath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.serialized_db_path', $this->testDbPath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.auto_serialize', false);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.use_hash_validation', true);

        // Create a fresh service provider instance
        $serviceProvider = new CitadelServiceProvider($this->app);

        // Use reflection to access the private createVectorscanPatternMatcher method
        $reflection = new \ReflectionClass($serviceProvider);
        $method = $reflection->getMethod('createVectorscanPatternMatcher');
        $method->setAccessible(true);

        // Create the matcher through the service provider
        $matcher = $method->invoke($serviceProvider, $this->testPatterns);

        // Verify the database was NOT created since auto-serialization is disabled
        $this->assertFalse(File::exists($this->testDbPath), 'Database file should not be created when auto-serialization is disabled');
    }

    /**
     * Test that the MultiPatternMatcher container binding works with hash validation
     */
    public function test_container_binding_works_with_hash_validation(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Configure for hash validation
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.implementation', 'vectorscan');
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.patterns_file', $this->testPatternsFilePath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.serialized_db_path', $this->testDbPath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.auto_serialize', true);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.use_hash_validation', true);

        // Get a MultiPatternMatcher from the container
        $matcher = $this->app->make(MultiPatternMatcher::class);

        // Verify it's a VectorScanMultiPatternMatcher
        $this->assertInstanceOf(VectorScanMultiPatternMatcher::class, $matcher);

        // Verify the database was created with hash
        $this->assertTrue(File::exists($this->testDbPath), 'Database file should be created');
        $this->assertTrue(File::exists($this->testDbPath.'.hash'), 'Hash file should be created');
    }

    /**
     * Test that the service provider handles non-writable directories gracefully
     */
    public function test_service_provider_handles_non_writable_directory(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Create a directory with no write permissions
        $nonWritablePath = storage_path('app/test/non_writable');
        if (! File::isDirectory($nonWritablePath)) {
            File::makeDirectory($nonWritablePath, 0555, true);
        }

        $nonWritableDbPath = $nonWritablePath.'/vectorscan_patterns.db';

        // Configure for hash validation with a non-writable path
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.implementation', 'vectorscan');
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.patterns_file', $this->testPatternsFilePath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.serialized_db_path', $nonWritableDbPath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.auto_serialize', true);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER.'.use_hash_validation', true);

        // Create a fresh service provider instance
        $serviceProvider = new CitadelServiceProvider($this->app);

        // Use reflection to access the private createVectorscanPatternMatcher method
        $reflection = new \ReflectionClass($serviceProvider);
        $method = $reflection->getMethod('createVectorscanPatternMatcher');
        $method->setAccessible(true);

        try {
            // Create the matcher through the service provider - should not throw
            $matcher = $method->invoke($serviceProvider, $this->testPatterns);

            // Verify the database was not created (since directory is not writable)
            $this->assertFalse(File::exists($nonWritableDbPath), 'Database file should not be created in non-writable directory');

            // But matcher should still be created and functional
            $this->assertInstanceOf(VectorScanMultiPatternMatcher::class, $matcher);

            // Test that the matcher works
            $matches = $matcher->scan('test123');
            $this->assertIsArray($matches);
        } catch (\Throwable $e) {
            // Only attempt to clean up the directory if we can
            try {
                if (File::isDirectory($nonWritablePath)) {
                    // Reset permissions
                    chmod($nonWritablePath, 0755);
                }
            } catch (\Throwable $e) {
                // Ignore cleanup errors
            }
            throw $e;
        }

        // Reset permissions for cleanup
        if (File::isDirectory($nonWritablePath)) {
            chmod($nonWritablePath, 0755);
        }
    }
}
