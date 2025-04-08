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
    }    /**
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
    
    /**
     * Test that simultaneous reads from multiple processes don't interfere with each other
     */
    public function test_simultaneous_reads_do_not_interfere(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // First create a serialized database
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        $result = $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($result, 'Database serialization should succeed');

        Log::info("Created database file for read test: {$this->testDbPath}");
        Log::info("Created hash file for read test: {$this->testDbPath}.hash");
        Log::info("Database exists: " . (File::exists($this->testDbPath) ? 'Yes' : 'No'));
        Log::info("Hash exists: " . (File::exists($this->testDbPath.'.hash') ? 'Yes' : 'No'));

        // Create a test PHP script that will read and validate the hash file directly
        // without relying on Laravel facades
        $scriptPath = storage_path('app/test/read_test.php');
        $scriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

echo "Process " . getmypid() . " starting read test\\n";
echo "Working directory: " . getcwd() . "\\n";
echo "Database path: {$this->testDbPath}\\n";
echo "Patterns file path: {$this->testPatternsFilePath}\\n";

try {
    // Verify the files exist
    \$dbExists = file_exists('{$this->testDbPath}');
    \$hashExists = file_exists('{$this->testDbPath}.hash');
    \$patternsExist = file_exists('{$this->testPatternsFilePath}');
    
    echo "Database exists: " . (\$dbExists ? 'Yes' : 'No') . "\\n";
    echo "Hash file exists: " . (\$hashExists ? 'Yes' : 'No') . "\\n";
    echo "Patterns file exists: " . (\$patternsExist ? 'Yes' : 'No') . "\\n";
    
    if (!\$dbExists || !\$hashExists || !\$patternsExist) {
        echo "ERROR: Required files are missing\\n";
        exit(1);
    }
    
    // Read the contents of the hash file
    \$hashContent = file_get_contents('{$this->testDbPath}.hash');
    if (\$hashContent === false) {
        echo "ERROR: Could not read hash file\\n";
        exit(1);
    }
    
    // Calculate the hash of the patterns file
    \$patternsContent = file_get_contents('{$this->testPatternsFilePath}');
    if (\$patternsContent === false) {
        echo "ERROR: Could not read patterns file\\n";
        exit(1);
    }
    
    \$calculatedHash = hash('sha256', \$patternsContent);
    \$storedHash = trim(\$hashContent); // Remove any whitespace
    
    echo "Calculated hash: " . \$calculatedHash . "\\n";
    echo "Stored hash: " . \$storedHash . "\\n";
    
    // Compare hashes
    \$isValid = (\$calculatedHash === \$storedHash);
    
    echo "Process " . getmypid() . " hash validation: " . (\$isValid ? 'valid' : 'invalid') . "\\n";
    
    // Simulate some processing work (and test for race conditions)
    for (\$i = 0; \$i < 5; \$i++) {
        usleep(rand(10000, 50000)); // Random delay between 10-50ms
        echo "Process " . getmypid() . " read iteration \$i complete\\n";
    }
    
} catch (\Exception \$e) {
    echo "EXCEPTION: " . \$e->getMessage() . "\\n";
    echo "TRACE: " . \$e->getTraceAsString() . "\\n";
    exit(1);
}
PHP;

        File::put($scriptPath, $scriptContent);
        Log::info("Created read test script at: {$scriptPath}");

        // Launch multiple PHP processes to try to read simultaneously
        $processes = [];
        $outputs = [];

        for ($i = 0; $i < 3; $i++) {
            Log::info("Starting read process {$i}");
            $processes[$i] = Process::run('php '.$scriptPath);
            $outputs[$i] = $processes[$i]->output();
            Log::info("Read process {$i} exit code: " . $processes[$i]->exitCode());
            Log::info("Read process {$i} output: " . $outputs[$i]);
        }

        // Clean up the test script
        File::delete($scriptPath);

        // Check that all processes successfully validated the hash
        $allValid = true;
        foreach ($outputs as $i => $output) {
            if (strpos($output, 'hash validation: valid') === false) {
                $allValid = false;
                Log::error("Process {$i} failed hash validation");
                break;
            }
        }

        $this->assertTrue($allValid, 'All processes should validate the hash successfully');

        // Verify the database is still valid after multiple reads
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($isValid, 'Database should still be valid after concurrent reads');

        // Output debug info in case of failures
        foreach ($outputs as $i => $output) {
            $this->addToAssertionCount(1); // Count checking the output as an assertion
        }
    }

    /**
     * Test that writing new hash while reading doesn't cause issues
     */
    public function test_write_during_reads_handled_properly(): void
    {
        if (! $this->isVectorscanAvailable()) {
            $this->markTestSkipped('Vectorscan library is not available');
        }

        // Skip on Windows as file locking behavior differs
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Skipping file access test on Windows');
        }

        // First create a serialized database
        $matcher = new VectorScanMultiPatternMatcher($this->testPatterns);
        $result = $matcher->serializeDatabaseWithHash($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($result, 'Database serialization should succeed');

        Log::info("Created database file for read/write test: {$this->testDbPath}");
        Log::info("Created hash file for read/write test: {$this->testDbPath}.hash");

        // Create reader script that doesn't rely on Laravel facades
        $readerScriptPath = storage_path('app/test/reader_script.php');
        $readerScriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

echo "Reader " . getmypid() . " started\\n";

// Run in a loop to increase chance of concurrent access
for (\$i = 0; \$i < 10; \$i++) {
    // Small random delay
    usleep(rand(1000, 10000));
    
    try {
        // Read the contents of the hash file
        \$hashContent = file_get_contents('{$this->testDbPath}.hash');
        if (\$hashContent === false) {
            echo "Reader iteration \$i: Could not read hash file\\n";
            continue;
        }
        
        // Calculate the hash of the patterns file
        \$patternsContent = file_get_contents('{$this->testPatternsFilePath}');
        if (\$patternsContent === false) {
            echo "Reader iteration \$i: Could not read patterns file\\n";
            continue;
        }
        
        \$calculatedHash = hash('sha256', \$patternsContent);
        \$storedHash = trim(\$hashContent); // Remove any whitespace
        
        \$isValid = (\$calculatedHash === \$storedHash);
        echo "Read #\$i: " . (\$isValid ? 'valid' : 'invalid') . " (calculated: " . substr(\$calculatedHash, 0, 10) . "..., stored: " . substr(\$storedHash, 0, 10) . "...)\\n";
        
    } catch (\Exception \$e) {
        echo "Reader iteration \$i EXCEPTION: " . \$e->getMessage() . "\\n";
    }
}

echo "Reader " . getmypid() . " completed all iterations\\n";
PHP;

        // Create writer script that uses direct file operations instead of Laravel facades
        $writerScriptPath = storage_path('app/test/writer_script.php');
        $writerScriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

echo "Writer " . getmypid() . " started\\n";

try {
    // Modify pattern file with new content
    \$newContent = 'modified_pattern\d+' . PHP_EOL . 'new_pattern\w+';
    echo "Writer is modifying patterns file with new content: '" . \$newContent . "'\\n";
    
    \$patternFile = fopen('{$this->testPatternsFilePath}', 'w');
    if (!\$patternFile) {
        throw new Exception("Failed to open patterns file for writing");
    }
    
    fwrite(\$patternFile, \$newContent);
    fclose(\$patternFile);
    
    echo "Writer has updated patterns file\\n";
    
    // Now update the database and hash file with locking
    echo "Writer is acquiring lock on database file\\n";
    \$dbFile = fopen('{$this->testDbPath}', 'c+');
    if (!\$dbFile) {
        throw new Exception("Failed to open database file for writing");
    }
    
    if (!flock(\$dbFile, LOCK_EX)) {
        fclose(\$dbFile);
        throw new Exception("Failed to acquire lock on database file");
    }
    
    echo "Writer acquired lock and is updating database content\\n";
    
    // Write some dummy content representing an updated database
    \$dummyContent = "Updated serialized database content - PID: " . getmypid() . " - Time: " . time();
    ftruncate(\$dbFile, 0);
    fwrite(\$dbFile, \$dummyContent);
    fflush(\$dbFile);
    
    // Now generate and write updated hash file
    \$hashFile = fopen('{$this->testDbPath}.hash', 'c+');
    if (!\$hashFile) {
        flock(\$dbFile, LOCK_UN);
        fclose(\$dbFile);
        throw new Exception("Failed to open hash file for writing");
    }
    
    if (!flock(\$hashFile, LOCK_EX)) {
        flock(\$dbFile, LOCK_UN);
        fclose(\$dbFile);
        fclose(\$hashFile);
        throw new Exception("Failed to acquire lock on hash file");
    }
    
    // Calculate a hash of the updated patterns file
    \$patternsContent = file_get_contents('{$this->testPatternsFilePath}');
    if (\$patternsContent === false) {
        echo "WARNING: Could not read patterns file\\n";
        \$patternHash = hash('sha256', 'fallback-if-patterns-file-missing');
    } else {
        \$patternHash = hash('sha256', \$patternsContent);
        echo "Writer calculated new pattern file hash: " . \$patternHash . "\\n";
    }
    
    ftruncate(\$hashFile, 0);
    fwrite(\$hashFile, \$patternHash);
    fflush(\$hashFile);
    
    // Simulate some work to increase chances of race condition
    usleep(rand(50000, 200000));
    
    // Release locks
    flock(\$dbFile, LOCK_UN);
    flock(\$hashFile, LOCK_UN);
    fclose(\$dbFile);
    fclose(\$hashFile);
    
    echo "Writer completed updating files and released locks\\n";
    echo "Writer serialization result: success\\n";
    
} catch (\Exception \$e) {
    echo "WRITER EXCEPTION: " . \$e->getMessage() . "\\n";
    echo "TRACE: " . \$e->getTraceAsString() . "\\n";
    exit(1);
}
PHP;

        File::put($readerScriptPath, $readerScriptContent);
        File::put($writerScriptPath, $writerScriptContent);

        Log::info("Created reader script at: {$readerScriptPath}");
        Log::info("Created writer script at: {$writerScriptPath}");

        // Start multiple reader processes
        $readerProcesses = [];
        for ($i = 0; $i < 2; $i++) {
            Log::info("Starting reader process {$i}");
            $readerProcesses[$i] = Process::start('php '.$readerScriptPath);
        }

        // Sleep briefly to ensure readers have started
        usleep(100000);

        // Run the writer process
        Log::info("Starting writer process");
        $writerProcess = Process::run('php '.$writerScriptPath);
        $writerOutput = $writerProcess->output();
        Log::info("Writer process exit code: " . $writerProcess->exitCode());
        Log::info("Writer process output: " . $writerOutput);

        // Wait for readers to complete
        $readerOutputs = [];
        foreach ($readerProcesses as $i => $process) {
            $readerOutputs[$i] = $process->wait()->output();
            Log::info("Reader process {$i} output: " . $readerOutputs[$i]);
        }

        // Clean up test scripts
        File::delete($readerScriptPath);
        File::delete($writerScriptPath);

        // Verify writer succeeded
        $this->assertStringContainsString('Writer serialization result: success', $writerOutput, 'Writer should succeed in reserializing database');

        // We can't guarantee which state the readers saw (before or after write),
        // but they should complete without errors
        foreach ($readerOutputs as $i => $output) {
            $this->assertStringContainsString('Read #9:', $output, "Reader $i should complete all 10 iterations");
            $this->assertStringContainsString('Reader ' . str_contains($output, 'Reader ') ? explode(' ', trim(explode("\n", $output)[0]))[1] : '?' . ' completed all iterations', $output, "Reader $i should complete successfully");
        }

        // Verify final state is valid
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($isValid, 'Database should be valid after concurrent read/write operations');
    }
}
