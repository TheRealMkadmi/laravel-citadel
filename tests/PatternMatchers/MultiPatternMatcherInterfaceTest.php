<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatcher;
use TheRealMkadmi\Citadel\PatternMatchers\PcreMultiPatternMatcher;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class MultiPatternMatcherInterfaceTest extends TestCase
{
    /**
     * @dataProvider provideMatcherImplementations
     */
    public function test_all_implementations_handle_serialization_correctly($implementationClass): void
    {
        try {
            // Create the implementation
            $patterns = ['test\d+'];
            $implementation = new $implementationClass($patterns);

            // Test interface methods related to serialization
            $serializedDbPath = storage_path('app/test/test_serialization.db');

            // All implementations should respond to supportsSerializedDatabase()
            $supportsDatabase = $implementation->supportsSerializedDatabase();

            // Attempt serialization (should work for supporting implementations, fail gracefully for others)
            $serializeResult = $implementation->serializeDatabase($serializedDbPath);

            if ($supportsDatabase) {
                // If serialization is supported, it should succeed
                $this->assertTrue($serializeResult, "$implementationClass claims to support serialization but failed to serialize");
            } else {
                // If serialization is not supported, it should return false
                $this->assertFalse($serializeResult, "$implementationClass claims not to support serialization but returned true");
            }

            // Test getSerializedDatabaseInfo
            $info = $implementation->getSerializedDatabaseInfo($serializedDbPath);
            if ($supportsDatabase && file_exists($serializedDbPath)) {
                // If supported and the file exists, we should get some info back
                $this->assertNotNull($info, "$implementationClass should return database info");
            } else {
                // Otherwise, we should get null
                $this->assertNull($info, "$implementationClass should return null for getSerializedDatabaseInfo");
            }

        } catch (\Throwable $e) {
            if ($implementationClass === VectorScanMultiPatternMatcher::class &&
                str_contains($e->getMessage(), 'libvectorscan shared library not found')) {
                $this->markTestSkipped('Vectorscan library not available');
            } else {
                throw $e;
            }
        }

        // Clean up
        if (isset($serializedDbPath) && file_exists($serializedDbPath)) {
            unlink($serializedDbPath);
        }

        if (isset($serializedDbPath) && file_exists($serializedDbPath.'.hash')) {
            unlink($serializedDbPath.'.hash');
        }
    }

    public function provideMatcherImplementations(): array
    {
        return [
            'PCRE Implementation' => [PcreMultiPatternMatcher::class],
            'Vectorscan Implementation' => [VectorScanMultiPatternMatcher::class],
        ];
    }

    public function test_implementations_correctly_report_serialization_support(): void
    {
        // PCRE should not support serialization
        $pcre = new PcreMultiPatternMatcher(['test\d+']);
        $this->assertFalse($pcre->supportsSerializedDatabase(), 'PCRE implementation should not support serialization');

        // Skip Vectorscan check if not available
        try {
            $vectorscan = new VectorScanMultiPatternMatcher(['test\d+']);
            $this->assertTrue($vectorscan->supportsSerializedDatabase(), 'Vectorscan implementation should support serialization');
        } catch (\Throwable $e) {
            if (str_contains($e->getMessage(), 'libvectorscan shared library not found')) {
                $this->markTestSkipped('Vectorscan library not available');
            } else {
                throw $e;
            }
        }
    }

    public function test_service_container_binds_correct_implementation(): void
    {
        // Configure to use PCRE
        $this->app['config']->set('citadel.pattern_matcher.implementation', 'pcre');
        $matcher = $this->app->make(MultiPatternMatcher::class);
        $this->assertInstanceOf(PcreMultiPatternMatcher::class, $matcher);

        // Configure to use Vectorscan
        $this->app['config']->set('citadel.pattern_matcher.implementation', 'vectorscan');

        try {
            $this->app->forgetInstance(MultiPatternMatcher::class);
            $matcher = $this->app->make(MultiPatternMatcher::class);
            $this->assertInstanceOf(VectorScanMultiPatternMatcher::class, $matcher);
        } catch (\Throwable $e) {
            if (str_contains($e->getMessage(), 'libvectorscan shared library not found')) {
                $this->markTestSkipped('Vectorscan library not available');
            } else {
                throw $e;
            }
        }
    }
}
