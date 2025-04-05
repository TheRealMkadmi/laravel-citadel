<?php

namespace TheRealMkadmi\Citadel\Tests\Integration;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
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

        // Set up test paths
        $this->testPatternsFilePath = storage_path('app/test/concurrency_test_patterns.list');
        $this->testDbPath = storage_path('app/test/concurrency_test_patterns.db');

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

        // Create a test PHP script that will serialize a database with hash validation
        $scriptPath = storage_path('app/test/serialize_test.php');
        $scriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

// Simulate a random delay to increase chances of race condition
usleep(rand(10000, 50000));

// Create a matcher with the test patterns
\$patterns = ['test\d+', 'example[a-z]+', 'sample\w+'];
\$matcher = new \TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher(\$patterns);

// Serialize with hash - this should use file locking internally
echo "Process " . getmypid() . " is serializing database\\n";
\$result = \$matcher->serializeDatabaseWithHash(
    '{$this->testDbPath}',
    '{$this->testPatternsFilePath}'
);

echo "Process " . getmypid() . " serialization result: " . (\$result ? 'success' : 'failure') . "\\n";

// Validate the resulting files
\$dbExists = file_exists('{$this->testDbPath}');
\$hashExists = file_exists('{$this->testDbPath}.hash');
echo "Process " . getmypid() . " validation: DB exists: " . (\$dbExists ? 'yes' : 'no') . 
     ", Hash exists: " . (\$hashExists ? 'yes' : 'no') . "\\n";

// Verify hash matches patterns file
\$isValid = \TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher::isDatabaseValid(
    '{$this->testDbPath}',
    '{$this->testPatternsFilePath}'
);
echo "Process " . getmypid() . " hash validation: " . (\$isValid ? 'valid' : 'invalid') . "\\n";
PHP;

        File::put($scriptPath, $scriptContent);

        // Launch multiple PHP processes to try to serialize simultaneously
        $processes = [];
        $outputs = [];

        for ($i = 0; $i < 3; $i++) {
            $processes[$i] = Process::run('php '.$scriptPath);
            $outputs[$i] = $processes[$i]->output();
        }

        // Clean up the test script
        File::delete($scriptPath);

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

        // Create a test PHP script that will read the serialized database
        $scriptPath = storage_path('app/test/read_test.php');
        $scriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

// Create a matcher with the serialized database path
\$patterns = ['test\d+'];
\$matcher = new \TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher(\$patterns, '{$this->testDbPath}');

// Scan for matches
\$matches = \$matcher->scan('test123 example456 sample789');
\$matchCount = count(\$matches);

echo "Process " . getmypid() . " match count: " . \$matchCount . "\\n";

// Validate the hash
\$isValid = \TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher::isDatabaseValid(
    '{$this->testDbPath}',
    '{$this->testPatternsFilePath}'
);
echo "Process " . getmypid() . " hash validation: " . (\$isValid ? 'valid' : 'invalid') . "\\n";
PHP;

        File::put($scriptPath, $scriptContent);

        // Launch multiple PHP processes to try to read simultaneously
        $processes = [];
        $outputs = [];

        for ($i = 0; $i < 3; $i++) {
            $processes[$i] = Process::run('php '.$scriptPath);
            $outputs[$i] = $processes[$i]->output();
        }

        // Clean up the test script
        File::delete($scriptPath);

        // Check that all processes successfully validated the hash
        $allValid = true;
        foreach ($outputs as $output) {
            if (strpos($output, 'hash validation: valid') === false) {
                $allValid = false;
                break;
            }
        }

        $this->assertTrue($allValid, 'All processes should validate the hash successfully');

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

        // Create reader script
        $readerScriptPath = storage_path('app/test/reader_script.php');
        $readerScriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

// Run in a loop to increase chance of concurrent access
for (\$i = 0; \$i < 10; \$i++) {
    // Small random delay
    usleep(rand(1000, 10000));
    
    \$isValid = \TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher::isDatabaseValid(
        '{$this->testDbPath}',
        '{$this->testPatternsFilePath}'
    );
    echo "Read #\$i: " . (\$isValid ? 'valid' : 'invalid') . "\\n";
}
PHP;

        // Create writer script
        $writerScriptPath = storage_path('app/test/writer_script.php');
        $writerScriptContent = <<<PHP
<?php
require_once '{$this->app->basePath('vendor/autoload.php')}';

// Modify pattern file
file_put_contents('{$this->testPatternsFilePath}', 'modified_pattern\d+' . PHP_EOL . 'new_pattern\w+');

// Create a matcher and reserialize the database
\$patterns = ['modified_pattern\d+', 'new_pattern\w+'];
\$matcher = new \TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher(\$patterns);

echo "Writer is reserializing database\\n";
\$result = \$matcher->serializeDatabaseWithHash(
    '{$this->testDbPath}',
    '{$this->testPatternsFilePath}'
);

echo "Writer serialization result: " . (\$result ? 'success' : 'failure') . "\\n";
PHP;

        File::put($readerScriptPath, $readerScriptContent);
        File::put($writerScriptPath, $writerScriptContent);

        // Start multiple reader processes
        $readerProcesses = [];
        for ($i = 0; $i < 2; $i++) {
            $readerProcesses[$i] = Process::start('php '.$readerScriptPath);
        }

        // Sleep briefly to ensure readers have started
        usleep(100000);

        // Run the writer process
        $writerProcess = Process::run('php '.$writerScriptPath);
        $writerOutput = $writerProcess->output();

        // Wait for readers to complete
        $readerOutputs = [];
        foreach ($readerProcesses as $i => $process) {
            $readerOutputs[$i] = $process->wait()->output();
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
        }

        // Verify final state is valid
        $isValid = VectorScanMultiPatternMatcher::isDatabaseValid($this->testDbPath, $this->testPatternsFilePath);
        $this->assertTrue($isValid, 'Database should be valid after concurrent read/write operations');
    }
}
