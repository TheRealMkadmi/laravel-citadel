<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use FFI;
use Illuminate\Support\Facades\File;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class VectorScanMultiPatternMatcherTest extends TestCase
{
    private string $testDbPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->testDbPath = storage_path('app/test/vectorscan_test_patterns.db');
        
        // Make sure the test directory exists
        if (!File::isDirectory(dirname($this->testDbPath))) {
            File::makeDirectory(dirname($this->testDbPath), 0755, true);
        }
        
        // Cleanup any existing test database file
        if (File::exists($this->testDbPath)) {
            File::delete($this->testDbPath);
        }
    }
    
    protected function tearDown(): void
    {
        // Cleanup the test database file
        if (File::exists($this->testDbPath)) {
            File::delete($this->testDbPath);
        }
        parent::tearDown();
    }

    public function test_scan_finds_single_match_per_pattern(): void
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

    public function test_library_loads_successfully(): void
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
    public function test_hs_mode_block_constant_is_defined_and_correct(): void
    {
        $reflection = new \ReflectionClass(VectorScanMultiPatternMatcher::class);
        $this->assertTrue($reflection->hasConstant('HS_MODE_BLOCK'), 'HS_MODE_BLOCK constant should be defined.');
        // Update the expected value from 0 to 1
        $this->assertSame(1, $reflection->getConstant('HS_MODE_BLOCK'), 'HS_MODE_BLOCK constant should be 1.');
    }

    /**
     * Test that getPatterns() returns the patterns provided in the constructor.
     */
    public function test_get_patterns_returns_correct_patterns(): void
    {
        $expectedPatterns = ['test\d+', 'foo\w*', 'bar[a-z]+'];
        $matcher = new VectorScanMultiPatternMatcher($expectedPatterns);

        $actualPatterns = $matcher->getPatterns();

        $this->assertSame($expectedPatterns, $actualPatterns);
    }

    /**
     * Test that scan() returns an empty array when no matches are found.
     */
    public function test_scan_with_no_matches(): void
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
    public function test_scan_with_empty_data(): void
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
    public function test_invalid_pattern_throws_exception(): void
    {
        $this->expectException(\RuntimeException::class);

        // This is an invalid regex pattern that should cause compilation to fail
        $patterns = ['test['];
        new VectorScanMultiPatternMatcher($patterns);
    }

    /**
     * Test that scan doesn't work if database is not initialized.
     */
    public function test_scan_throws_exception_if_database_not_initialized(): void
    {
        // Expect any type of exception that contains the specific message
        $this->expectExceptionMessage('Vectorscan database or scratch space not initialized');

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
    
    /**
     * Test serialization and deserialization of the pattern database
     */
    public function test_serialize_and_deserialize_database(): void
    {
        // Create test patterns
        $patterns = ['test\d+', 'foo\w*', 'bar[a-z]+'];
        
        // Create a matcher and compile patterns
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        
        // Serialize the database to a test file
        $result = $matcher->serializeDatabase($this->testDbPath);
        
        // Assert serialization success
        $this->assertTrue($result, 'Database serialization should succeed');
        $this->assertTrue(File::exists($this->testDbPath), 'Serialized database file should exist');
        
        // Get file info to verify it's not empty
        $fileSize = File::size($this->testDbPath);
        $this->assertGreaterThan(0, $fileSize, 'Serialized database file should not be empty');
        
        // Create a new matcher instance with the same patterns but provide the serialized database path
        $deserializedMatcher = new VectorScanMultiPatternMatcher($patterns, $this->testDbPath);
        
        // Perform a scan with the deserialized database to verify functionality
        $inputData = 'test123 and foo_bar and barxyz';
        $matches = $deserializedMatcher->scan($inputData);
        
        // Assert that patterns still work with the deserialized database
        $this->assertNotEmpty($matches, 'Deserializing should produce a working database');
        $this->assertCount(1, $matches, 'With SINGLEMATCH flag, there should be one match');
        $this->assertSame('test1', $matches[0]->matchedSubstring);
    }
    
    /**
     * Test getting information about a serialized database
     */
    public function test_get_serialized_database_info(): void
    {
        // Create a matcher with test patterns and serialize it
        $patterns = ['test\d+', 'example[a-z]+'];
        $matcher = new VectorScanMultiPatternMatcher($patterns);
        $matcher->serializeDatabase($this->testDbPath);
        
        // Get info about the serialized database
        $info = $matcher->getSerializedDatabaseInfo($this->testDbPath);
        
        // Assert info string contains expected details
        $this->assertNotNull($info, 'Database info should not be null');
        $this->assertIsString($info, 'Database info should be a string');
        $this->assertStringContainsString('Version', $info, 'Info should include version details');
        
        // Test with non-existent file
        $nonExistentPath = storage_path('app/test/non_existent.db');
        $infoResult = $matcher->getSerializedDatabaseInfo($nonExistentPath);
        $this->assertNull($infoResult, 'Info for non-existent file should be null');
    }
    
    /**
     * Test fallback to compilation when loading from a non-existent database
     */
    public function test_fallback_to_compilation_when_db_not_found(): void
    {
        $patterns = ['test\d+'];
        $nonExistentPath = storage_path('app/test/non_existent.db');
        
        // Should fall back to compilation when path doesn't exist
        $matcher = new VectorScanMultiPatternMatcher($patterns, $nonExistentPath);
        
        // Verify the matcher still works (meaning compilation occurred)
        $matches = $matcher->scan('test123');
        $this->assertNotEmpty($matches, 'Matcher should fall back to compilation');
    }
}
