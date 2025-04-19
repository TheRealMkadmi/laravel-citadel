<?php

namespace TheRealMkadmi\Citadel\Tests\Commands;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class CitadelCompileRegexCommandTest extends TestCase
{
    /**
     * Constants for test paths
     */
    private const TEST_DIRECTORY_PREFIX = 'citadel-test-';
    private const TEST_PATTERNS_FILENAME = 'test_patterns.list';
    private const TEST_OUTPUT_FILENAME = 'test_patterns.db';
    private const TEST_STORAGE_PATH = 'app/test';
    private const DEFAULT_DB_PATH = 'app/citadel/vectorscan_patterns.db';

    /**
     * Test state variables
     */
    private string $testPatternsFile;
    private string $testOutputPath;
    private array $testPatterns = ['pattern1', 'pattern2', 'pattern3'];
    private string $testDir;
    
    /**
     * Set up the testing environment
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up unique test directory with proper path handling
        $testId = uniqid();
        $this->testDir = storage_path(self::TEST_STORAGE_PATH . '/' . self::TEST_DIRECTORY_PREFIX . $testId);
        
        // Ensure test directory exists with proper permissions
        $this->ensureDirectoryExists($this->testDir);
        
        // Set up pattern file
        $this->testPatternsFile = $this->testDir . '/' . self::TEST_PATTERNS_FILENAME;
        File::put($this->testPatternsFile, implode(PHP_EOL, $this->testPatterns));
        
        // Set up output path
        $this->testOutputPath = $this->testDir . '/' . self::TEST_OUTPUT_FILENAME;
        
        // Ensure citadel default directory exists too
        $this->ensureDirectoryExists(dirname(storage_path(self::DEFAULT_DB_PATH)));
        
        // Configure pattern matcher with explicit paths
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER . '.patterns_file', $this->testPatternsFile);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER . '.serialized_db_path', $this->testOutputPath);
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER . '.implementation', 'vectorscan');
        
        // Log setup details for debugging
        Log::info('CitadelCompileRegexCommandTest setup', [
            'testDir' => $this->testDir,
            'testPatternsFile' => $this->testPatternsFile,
            'testOutputPath' => $this->testOutputPath,
            'patternFileExists' => File::exists($this->testPatternsFile),
        ]);
    }
    
    /**
     * Clean up the testing environment
     */
    protected function tearDown(): void
    {
        // Clean up test directory if it exists
        if (File::isDirectory($this->testDir)) {
            try {
                File::deleteDirectory($this->testDir);
            } catch (\Throwable $e) {
                Log::warning('Failed to clean up test directory: ' . $e->getMessage());
            }
        }
        
        // Clean up default path if it was used
        $defaultPath = storage_path(self::DEFAULT_DB_PATH);
        if (File::exists($defaultPath)) {
            try {
                File::delete($defaultPath);
            } catch (\Throwable $e) {
                Log::warning('Failed to delete default database file: ' . $e->getMessage());
            }
        }
        
        $hashFile = $defaultPath . VectorScanMultiPatternMatcher::HASH_FILENAME_SUFFIX;
        if (File::exists($hashFile)) {
            try {
                File::delete($hashFile);
            } catch (\Throwable $e) {
                Log::warning('Failed to delete hash file: ' . $e->getMessage());
            }
        }
        
        parent::tearDown();
    }
    
    /**
     * Helper method to ensure a directory exists
     */
    private function ensureDirectoryExists(string $path): void
    {
        if (!File::isDirectory($path)) {
            // Create with explicit permissions and recursive flag
            File::makeDirectory($path, 0755, true);
            
            // Verify directory was created successfully
            if (!File::isDirectory($path)) {
                $this->fail("Failed to create test directory: {$path}");
            }
        }
    }
    
    /**
     * Test successful pattern compilation
     */
    public function testSuccessfulCompilation()
    {
        // Execute command
        $result = $this->artisan('citadel:compile-regex');
        
        // Assert expected output
        $result->expectsOutput('Pattern database successfully compiled and serialized.')
               ->assertExitCode(0);
        
        // Log path information for debugging
        Log::info('Checking output file', [
            'path' => $this->testOutputPath,
            'exists' => File::exists($this->testOutputPath),
            'directory' => File::isDirectory(dirname($this->testOutputPath)),
        ]);
        
        // Verify file was actually created
        $this->assertTrue(File::exists($this->testOutputPath), 'Database file should exist');
        $this->assertGreaterThan(0, File::size($this->testOutputPath), 'Database file should not be empty');
    }
    
    /**
     * Test error when pattern file doesn't exist
     */
    public function testPatternFileNotFound()
    {
        // Set non-existent pattern file path
        $nonExistentFile = storage_path('app/test/non_existent_file.txt');
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER . '.patterns_file', $nonExistentFile);
        
        // Execute command
        $this->artisan('citadel:compile-regex')
             ->expectsOutput("Pattern file not found: {$nonExistentFile}")
             ->assertExitCode(1);
    }
    
    /**
     * Test error when pattern file is empty
     */
    public function testEmptyPatternsFile()
    {
        // Create empty patterns file
        File::put($this->testPatternsFile, '');
        
        // Execute command
        $this->artisan('citadel:compile-regex')
             ->expectsOutput('No valid patterns found in patterns file.')
             ->assertExitCode(1);
    }
    
    /**
     * Test force option for overwriting existing database
     */
    public function testForceOption()
    {
        // Create the database file first
        $this->artisan('citadel:compile-regex');
        
        // Verify file exists after first run
        $this->assertTrue(File::exists($this->testOutputPath), 'Database file should exist after first compilation');
        
        // Get initial modification time
        $initialModTime = File::lastModified($this->testOutputPath);
        
        // Short delay to ensure modification time will be different
        sleep(1);
        
        // Run again with force option
        $this->artisan('citadel:compile-regex', ['--force' => true])
             ->expectsOutput('Pattern database successfully compiled and serialized.')
             ->assertExitCode(0);
             
        // Verify file was recreated with newer timestamp
        $this->assertTrue(File::exists($this->testOutputPath), 'Database file should exist after forced compilation');
        $this->assertGreaterThan($initialModTime, File::lastModified($this->testOutputPath), 'File should have newer timestamp');
    }
    
    /**
     * Test using custom paths via command options
     */
    public function testCustomPathsOptions()
    {
        // Create custom paths
        $testDir = dirname($this->testPatternsFile);
        $customPatternsFile = "{$testDir}/custom_patterns.list";
        $customOutputPath = "{$testDir}/custom_patterns.db";
        
        // Create custom patterns file
        File::put($customPatternsFile, implode(PHP_EOL, ['custom1', 'custom2', 'custom3']));
        
        // Execute command with custom paths
        $this->artisan('citadel:compile-regex', [
                '--patterns' => $customPatternsFile,
                '--path' => $customOutputPath
             ])
             ->expectsOutput('Pattern database successfully compiled and serialized.')
             ->expectsOutput("Output file: {$customOutputPath}")
             ->assertExitCode(0);
             
        // Verify output file was created
        $this->assertTrue(File::exists($customOutputPath), 'Custom output file should exist');
        $this->assertGreaterThan(0, File::size($customOutputPath), 'Custom output file should not be empty');
    }
    
    /**
     * Test confirmation prompt when file exists
     */
    public function testConfirmationPromptWhenFileExists()
    {
        // Create the database file first
        $this->artisan('citadel:compile-regex');
        
        // Verify file exists
        $this->assertTrue(File::exists($this->testOutputPath), 'Database file should exist after first compilation');
        
        // Get initial modification time
        $initialModTime = File::lastModified($this->testOutputPath);
        
        // Short delay to ensure modification time will be different
        sleep(1);
        
        // Run again, confirming when prompted
        $this->artisan('citadel:compile-regex')
             ->expectsQuestion('Database file already exists. Do you want to overwrite it?', true)
             ->expectsOutput('Pattern database successfully compiled and serialized.')
             ->assertExitCode(0);
             
        // Verify file was recreated
        $this->assertGreaterThan($initialModTime, File::lastModified($this->testOutputPath), 
            'File should have newer timestamp after confirmation');
    }
    
    /**
     * Test default output path when none specified
     */
    public function testDefaultOutputPathWhenNoneSpecified()
    {
        // Remove output path from config to test default behavior
        Config::set(CitadelConfig::KEY_PATTERN_MATCHER . '.serialized_db_path', null);
        
        // Default path according to command
        $defaultPath = storage_path(self::DEFAULT_DB_PATH);
        
        // Explicitly ensure the default directory exists with proper permissions
        $defaultDir = dirname($defaultPath);
        $this->ensureDirectoryExists($defaultDir);
        
        // Verify test conditions
        $this->assertDirectoryExists($defaultDir, 'Default output directory must exist');
        $this->assertDirectoryIsWritable($defaultDir, 'Default output directory must be writable');
        
        // Make sure any old database is removed
        if (File::exists($defaultPath)) {
            File::delete($defaultPath);
        }
        
        // Execute command
        $result = $this->artisan('citadel:compile-regex');
        
        // Check output and exit code
        $result->expectsOutput("No output path specified, using default: {$defaultPath}")
               ->expectsOutput('Pattern database successfully compiled and serialized.')
               ->assertExitCode(0);
        
        // Verify default file was created
        $this->assertTrue(File::exists($defaultPath), 'Default database file should exist');
        $this->assertGreaterThan(0, File::size($defaultPath), 'Default database file should not be empty');
    }
}
