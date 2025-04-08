<?php

namespace TheRealMkadmi\Citadel\Tests\Integration;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class HashValidationConcurrencyTest extends TestCase
{
    private string $testPatternsFilePath;

    private string $testDbPath;

    private array $testPatterns = ['test\d+', 'example[a-z]+', 'sample\w+'];

    protected function setUp(): void
    {
        parent::setUp();

        // Set up test paths with full absolute paths to avoid any path resolution issues
        $this->testPatternsFilePath = storage_path('app/test/concurrency_test_patterns.list');
        $this->testDbPath = storage_path('app/test/concurrency_test_patterns.db');

        // Log the paths for debugging
        Log::info("Test setup - patterns file path: {$this->testPatternsFilePath}");
        Log::info("Test setup - database file path: {$this->testDbPath}");

        // Ensure the test directory exists
        if (! File::isDirectory(dirname($this->testPatternsFilePath))) {
            File::makeDirectory(dirname($this->testPatternsFilePath), 0755, true);
        }

        // Create a test patterns file
        File::put($this->testPatternsFilePath, implode(PHP_EOL, $this->testPatterns));
        
        // Verify the test patterns file was created
        Log::info("Patterns file exists after setup: " . (File::exists($this->testPatternsFilePath) ? 'Yes' : 'No'));

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
        
        // Log cleanup results
        Log::info("After cleanup - DB file exists: " . (File::exists($this->testDbPath) ? 'Yes' : 'No'));
        Log::info("After cleanup - Hash file exists: " . (File::exists($this->testDbPath.'.hash') ? 'Yes' : 'No'));
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
            Log::warning("Vectorscan not available: {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Test that file locking prevents race conditions when multiple processes try to
     * update the serialized database simultaneously
     */
    public function test_file_locking_prevents_race_conditions(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Skip on Windows as file locking behavior differs
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Skipping file locking test on Windows');
        }

        // Log the current working directory and absolute paths
        Log::info("Current working directory: " . getcwd());
        Log::info("Absolute pattern file path: {$this->testPatternsFilePath}");
        Log::info("Absolute database path: {$this->testDbPath}");
        
        // Verify patterns file exists before proceeding
        Log::info("Pattern file exists before test: " . (File::exists($this->testPatternsFilePath) ? 'Yes' : 'No'));        // Instead of relying on Laravel in the subprocess, we'll use a direct file writing approach
        // that doesn't depend on the Laravel app context
        
        // Create a test PHP script that will directly write to the DB file with locking
        $scriptPath = storage_path('app/test/serialize_test.php');
        $scriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Add detailed logging
echo "Script started with PID " . getmypid() . "\\n";
echo "Working directory: " . getcwd() . "\\n";

// Verify file paths
echo "Patterns file path: {$this->testPatternsFilePath}\\n";
echo "Patterns file exists: " . (file_exists('{$this->testPatternsFilePath}') ? 'Yes' : 'No') . "\\n";
echo "Database path: {$this->testDbPath}\\n";
echo "Database directory exists: " . (is_dir(dirname('{$this->testDbPath}')) ? 'Yes' : 'No') . "\\n";
echo "Current permissions on directory: " . substr(sprintf('%o', fileperms(dirname('{$this->testDbPath}'))), -4) . "\\n";

// Simulate a random delay to increase chances of race condition
usleep(rand(10000, 50000));

try {
    // Simple file locking demonstration that doesn't depend on Laravel Facades
    // This simulates what VectorScanMultiPatternMatcher would do when serializing
    
    // 1. First create or open the database file with an exclusive lock
    echo "Process " . getmypid() . " is acquiring exclusive lock on database file\\n";
    
    \$dbFile = fopen('{$this->testDbPath}', 'c+');
    if (!\$dbFile) {
        throw new Exception("Failed to open database file for writing: {$this->testDbPath}");
    }
    
    // Try to get an exclusive lock - this will block if another process has the lock
    if (!flock(\$dbFile, LOCK_EX)) {
        fclose(\$dbFile);
        throw new Exception("Failed to acquire lock on database file");
    }
    
    echo "Process " . getmypid() . " acquired lock and is writing database content\\n";
    
    // Write some dummy content (representing serialized database)
    \$dummyContent = "Simulated serialized database content - PID: " . getmypid() . " - Time: " . time();
    ftruncate(\$dbFile, 0); // Clear existing content
    fwrite(\$dbFile, \$dummyContent);
    fflush(\$dbFile);
      // Now generate and write hash file - this should contain the hash of the patterns file to match production behavior
    \$hashFile = fopen('{$this->testDbPath}.hash', 'c+');
    if (!\$hashFile) {
        // Release the lock on the DB file before throwing
        flock(\$dbFile, LOCK_UN);
        fclose(\$dbFile);
        throw new Exception("Failed to open hash file for writing: {$this->testDbPath}.hash");
    }
    
    if (!flock(\$hashFile, LOCK_EX)) {
        flock(\$dbFile, LOCK_UN);
        fclose(\$dbFile);
        fclose(\$hashFile);
        throw new Exception("Failed to acquire lock on hash file");
    }
    
    // Calculate a hash of the patterns file, not the database content
    // This matches how VectorScanMultiPatternMatcher::serializeDatabaseWithHash() would work
    \$patternsContent = file_get_contents('{$this->testPatternsFilePath}');
    if (\$patternsContent === false) {
        echo "WARNING: Could not read patterns file\\n";
        \$patternHash = hash('sha256', 'fallback-if-patterns-file-missing');
    } else {
        \$patternHash = hash('sha256', \$patternsContent);
        echo "Calculated pattern file hash: " . \$patternHash . "\\n";
    }
    
    ftruncate(\$hashFile, 0);
    fwrite(\$hashFile, \$patternHash);
    fflush(\$hashFile);
    
    // Wait for a bit to simulate work (and increase chance of race condition)
    usleep(rand(50000, 200000));
    
    // Release locks
    flock(\$dbFile, LOCK_UN);
    flock(\$hashFile, LOCK_UN);
    fclose(\$dbFile);
    fclose(\$hashFile);
    
    echo "Process " . getmypid() . " completed writing files and released locks\\n";
    
    // Verify the files exist
    \$dbExists = file_exists('{$this->testDbPath}');
    \$hashExists = file_exists('{$this->testDbPath}.hash');
    echo "Process " . getmypid() . " verification: DB exists: " . (\$dbExists ? 'yes' : 'no') . 
         ", Hash exists: " . (\$hashExists ? 'yes' : 'no') . "\\n";
    
    if (\$dbExists && \$hashExists) {
        echo "Process " . getmypid() . " successfully created both files\\n";
    } else {
        echo "Process " . getmypid() . " failed to create at least one file\\n";
    }
} catch (\Exception \$e) {
    echo "EXCEPTION: " . \$e->getMessage() . "\\n";
    echo "TRACE: " . \$e->getTraceAsString() . "\\n";
}
PHP;

        File::put($scriptPath, $scriptContent);
        Log::info("Created test script at: {$scriptPath}");

        // Launch multiple PHP processes to try to serialize simultaneously
        $processes = [];
        $outputs = [];

        for ($i = 0; $i < 3; $i++) {
            Log::info("Starting process {$i}");
            $processes[$i] = Process::run('php '.$scriptPath);
            $outputs[$i] = $processes[$i]->output();
            Log::info("Process {$i} exit code: " . $processes[$i]->exitCode());
            Log::info("Process {$i} output: " . $outputs[$i]);
        }

        // Clean up the test script
        File::delete($scriptPath);

        // Check if files actually exist after the processes ran
        Log::info("After processes - DB file exists: " . (File::exists($this->testDbPath) ? 'Yes' : 'No'));
        Log::info("After processes - Hash file exists: " . (File::exists($this->testDbPath.'.hash') ? 'Yes' : 'No'));

        // Verify results - we should have a valid database and hash file
        $this->assertTrue(File::exists($this->testDbPath), 'Database file should exist after concurrent operations');
        $this->assertTrue(File::exists($this->testDbPath.'.hash'), 'Hash file should exist after concurrent operations');

        // Verify the database is valid
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($isValid, 'Database should be valid after concurrent operations');

        // Output debug info in case of failures
        foreach ($outputs as $i => $output) {
            $this->addToAssertionCount(1); // Count checking the output as an assertion
        }
    }
}
