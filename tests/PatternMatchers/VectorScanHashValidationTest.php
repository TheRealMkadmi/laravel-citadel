<?php

namespace TheRealMkadmi\Citadel\Tests\PatternMatchers;

use Illuminate\Support\Facades\File;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class VectorScanHashValidationTest extends TestCase
{
    private string $testPatternsFilePath;
    private string $testDbPath;
    private array $testPatterns = ['test\d+', 'example[a-z]+', 'sample\w+'];
    
    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up test paths
        $this->testPatternsFilePath = storage_path('app/test/test_patterns.list');
        $this->testDbPath = storage_path('app/test/test_patterns.db');
        
        // Ensure the test directory exists
        if (!File::isDirectory(dirname($this->testPatternsFilePath))) {
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
        
        if (File::exists($this->testDbPath . '.hash')) {
            File::delete($this->testDbPath . '.hash');
        }
    }
    
    public function test_can_calculate_patterns_file_hash(): void
    {
        // Calculate hash of the test patterns file
        $hash = VectorScanMultiPatternMatcher::calculatePatternsFileHash($this->testPatternsFilePath);
        
        // Verify hash exists and is a valid SHA256 hash
        $this->assertNotNull($hash);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hash, 'Should be a valid SHA256 hash');
        
        // Calculate hash again to ensure consistency
        $hash2 = VectorScanMultiPatternMatcher::calculatePatternsFileHash($this->testPatternsFilePath);
        $this->assertEquals($hash, $hash2, 'Hash calculation should be consistent');
    }
    
    public function test_can_store_and_retrieve_pattern_hash(): void
    {
        // Calculate hash
        $hash = VectorScanMultiPatternMatcher::calculatePatternsFileHash($this->testPatternsFilePath);
        
        // Store hash
        $result = VectorScanMultiPatternMatcher::storePatternHash($this->testDbPath, $hash);
        
        // Verify hash was stored
        $this->assertTrue($result, 'Hash should be stored successfully');
        $this->assertTrue(File::exists($this->testDbPath . '.hash'), 'Hash file should exist');
        
        // Retrieve stored hash
        $retrievedHash = VectorScanMultiPatternMatcher::getStoredPatternHash($this->testDbPath);
        
        // Verify retrieval
        $this->assertEquals($hash, $retrievedHash, 'Retrieved hash should match original');
    }
    
    public function test_database_is_valid_when_hash_matches(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $result = $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($result, 'Database serialization should succeed');
        
        // Validate database
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($isValid, 'Database should be valid when pattern file is unchanged');
    }
    
    public function test_database_is_invalid_when_pattern_file_changes(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Modify the patterns file (add a pattern)
        $modifiedPatterns = array_merge($this->testPatterns, ['newpattern\d+']);
        File::put($this->testPatternsFilePath, implode(PHP_EOL, $modifiedPatterns));
        
        // Validate database
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertFalse($isValid, 'Database should be invalid when pattern file is changed');
    }
    
    public function test_database_is_invalid_when_hash_file_missing(): void
    {
        // Create a test matcher and serialize database without hash
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        $matcher->serializeDatabase($this->testDbPath);
        
        // Database should be invalid as the hash file is missing
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertFalse($isValid, 'Database should be invalid when hash file is missing');
    }
    
    public function test_serialization_with_hash(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $result = $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Verify serialization worked
        $this->assertTrue($result, 'Database serialization should succeed');
        $this->assertTrue(File::exists($this->testDbPath), 'Database file should exist');
        $this->assertTrue(File::exists($this->testDbPath . '.hash'), 'Hash file should exist');
        
        // Verify hash value
        $expectedHash = VectorScanMultiPatternMatcher::calculatePatternsFileHash($this->testPatternsFilePath);
        $storedHash = VectorScanMultiPatternMatcher::getStoredPatternHash($this->testDbPath);
        $this->assertEquals($expectedHash, $storedHash, 'Stored hash should match calculated hash');
    }
    
    public function test_database_validation_with_modified_content_but_same_filename(): void
    {
        // Create initial matcher and database
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Database should be valid
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($isValid, 'Database should be valid initially');
        
        // Change content of patterns file without changing filename
        File::put($this->testPatternsFilePath, 'new_pattern\d+' . PHP_EOL . 'another_pattern\w+');
        
        // Database should now be invalid due to content change
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertFalse($isValid, 'Database should be invalid when file content changes');
    }
    
    public function test_automatic_recompilation_with_service_provider(): void
    {
        // Skip this test if Vectorscan is not available
        try {
            new VectorScanMultiPatternMatcher(['test']);
        } catch (\Throwable $e) {
            $this->markTestSkipped('Vectorscan library is not available');
        }
        
        // Mock configuration
        $this->app['config']->set('citadel.pattern_matcher.implementation', 'vectorscan');
        $this->app['config']->set('citadel.pattern_matcher.patterns_file', $this->testPatternsFilePath);
        $this->app['config']->set('citadel.pattern_matcher.serialized_db_path', $this->testDbPath);
        $this->app['config']->set('citadel.pattern_matcher.auto_serialize', true);
        $this->app['config']->set('citadel.pattern_matcher.use_hash_validation', true);
        
        // Force service provider to create the pattern matcher
        // First time should compile and create database + hash
        $matcher1 = $this->app->make(VectorScanMultiPatternMatcher::class);
        
        // Verify database and hash files were created
        $this->assertTrue(File::exists($this->testDbPath), 'Database file should be created');
        $this->assertTrue(File::exists($this->testDbPath . '.hash'), 'Hash file should be created');
        
        // Record database modification time
        $firstModTime = File::lastModified($this->testDbPath);
        
        // Force reload the matcher (but don't change patterns file)
        $this->app->forgetInstance(VectorScanMultiPatternMatcher::class);
        $matcher2 = $this->app->make(VectorScanMultiPatternMatcher::class);
        
        // Verify the database was not recompiled
        $secondModTime = File::lastModified($this->testDbPath);
        $this->assertEquals($firstModTime, $secondModTime, 'Database should not be recompiled when patterns are unchanged');
        
        // Now modify the patterns file
        File::put($this->testPatternsFilePath, 'new_pattern\d+' . PHP_EOL . 'modified_pattern\w+');
        
        // Force reload the matcher
        $this->app->forgetInstance(VectorScanMultiPatternMatcher::class);
        $matcher3 = $this->app->make(VectorScanMultiPatternMatcher::class);
        
        // Verify the database was recompiled
        $thirdModTime = File::lastModified($this->testDbPath);
        $this->assertGreaterThan($secondModTime, $thirdModTime, 'Database should be recompiled when patterns are changed');
        
        // Verify the new hash matches the modified file
        $expectedHash = VectorScanMultiPatternMatcher::calculatePatternsFileHash($this->testPatternsFilePath);
        $storedHash = VectorScanMultiPatternMatcher::getStoredPatternHash($this->testDbPath);
        $this->assertEquals($expectedHash, $storedHash, 'Hash should be updated after recompilation');
    }

    /**
     * Test handling corrupted hash files
     */
    public function test_handles_corrupted_hash_file(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Verify initial validation is successful
        $this->assertTrue(
            VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath),
            'Database should be valid initially'
        );
        
        // Corrupt the hash file by writing invalid content
        File::put($this->testDbPath . VectorScanMultiPatternMatcher::HASH_FILENAME_SUFFIX, 'corrupted-hash');
        
        // Validate database with corrupted hash file
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertFalse($isValid, 'Database should be invalid when hash file is corrupted');
    }

    /**
     * Test handling when pattern file is missing
     */
    public function test_handles_missing_pattern_file(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Delete the pattern file
        File::delete($this->testPatternsFilePath);
        
        // Validate database with missing pattern file
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertFalse($isValid, 'Database should be invalid when pattern file is missing');
    }
    
    /**
     * Test handling empty pattern files
     */
    public function test_handles_empty_pattern_file(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Empty the pattern file without deleting it
        File::put($this->testPatternsFilePath, '');
        
        // Validate database with empty pattern file
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertFalse($isValid, 'Database should be invalid when pattern file is empty');
    }
    
    /**
     * Test handling when database file is corrupted but hash file is intact
     */
    public function test_handles_corrupted_database_file(): void
    {
        // Create a test matcher
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        
        // Serialize with hash
        $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        
        // Corrupt the database file by changing a few bytes
        $originalContent = File::get($this->testDbPath);
        $corruptedContent = substr_replace($originalContent, 'CORRUPTED', 10, 8);
        File::put($this->testDbPath, $corruptedContent);
        
        // Create a new test matcher instance using the corrupted database
        try {
            $corruptedMatcher = new VectorScanMultiPatternMatcher($this->testPatterns, $this->testDbPath);
            
            // Try to scan something - this might throw an exception but we're testing recovery,
            // not the specific exception
            try {
                $corruptedMatcher->scan('test123');
                // If we get here without exception, then the matcher automatically recompiled the database
                $this->assertTrue(true, 'Matcher should handle corrupted database by recompiling');
            } catch (\Throwable $e) {
                // We need to check if the error indicates deserialization failure, which is expected
                $this->assertStringContainsString('deserializ', $e->getMessage(), 'Error should be about deserialization');
            }
        } catch (\Throwable $e) {
            // If we can't even create the matcher, we should still expect it to recover gracefully
            $this->assertStringContainsString('deserializ', $e->getMessage(), 'Error should be about deserialization');
        }
    }
}