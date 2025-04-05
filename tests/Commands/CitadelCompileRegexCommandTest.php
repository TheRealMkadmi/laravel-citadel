<?php

namespace TheRealMkadmi\Citadel\Tests\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class CitadelCompileRegexCommandTest extends TestCase
{
    private string $testDbPath;
    private string $testPatternPath;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up test paths
        $this->testDbPath = storage_path('app/test/command_test_patterns.db');
        $this->testPatternPath = storage_path('app/test/test_patterns.list');
        
        // Ensure test directories exist
        if (!File::isDirectory(dirname($this->testDbPath))) {
            File::makeDirectory(dirname($this->testDbPath), 0755, true);
        }
        
        // Create a test patterns file
        $patterns = <<<EOT
# Test patterns file
test\d+
example[a-z]+
# Another comment
foo\w*
EOT;
        File::put($this->testPatternPath, $patterns);
        
        // Clean up any existing database file
        if (File::exists($this->testDbPath)) {
            File::delete($this->testDbPath);
        }
    }
    
    protected function tearDown(): void
    {
        // Clean up test files
        if (File::exists($this->testDbPath)) {
            File::delete($this->testDbPath);
        }
        
        if (File::exists($this->testPatternPath)) {
            File::delete($this->testPatternPath);
        }
        
        parent::tearDown();
    }
    
    public function test_command_compiles_and_serializes_database()
    {
        try {
            // Configure the test
            $this->app['config']->set('citadel.pattern_matcher.patterns_file', $this->testPatternPath);
            
            // Execute the command
            $result = $this->artisan('citadel:compile-regex', [
                '--path' => $this->testDbPath,
                '--force' => true,
            ]);

            // Check if the command executed successfully
            $result->assertExitCode(0);
            
            // Verify the database file was created
            $this->assertTrue(File::exists($this->testDbPath), 'Database file should be created');
            $this->assertGreaterThan(0, File::size($this->testDbPath), 'Database file should not be empty');
            
            // Attempt to load the serialized database with the VectorScanMultiPatternMatcher
            try {
                $patterns = ['test\d+']; // Doesn't matter what we pass, it should load from file
                $matcher = new VectorScanMultiPatternMatcher($patterns, $this->testDbPath);
                
                // Verify the database works by scanning a test string
                $matches = $matcher->scan('test123 example and foo');
                $this->assertNotEmpty($matches, 'Pattern matcher should find matches after loading the serialized database');
            } catch (\RuntimeException $e) {
                // If we can't load the VectorScan library, that's okay for this test
                if (stripos($e->getMessage(), 'library not found') !== false) {
                    $this->markTestSkipped('VectorScan library not found, skipping verification part.');
                } else {
                    throw $e;
                }
            }
        } catch (\Throwable $e) {
            // If something goes wrong, we want to know about it
            if (stripos($e->getMessage(), 'library not found') !== false) {
                $this->markTestSkipped('VectorScan library not found, skipping test.');
            } else {
                throw $e;
            }
        }
    }
    
    public function test_command_respects_force_flag()
    {
        // First create a database file
        File::put($this->testDbPath, 'dummy content');
        $originalContent = 'dummy content';
        $originalTime = filemtime($this->testDbPath);
        
        // Wait a moment to ensure file modification time would be different
        sleep(1);
        
        // Run command without --force
        $this->artisan('citadel:compile-regex', [
            '--path' => $this->testDbPath,
            '--patterns' => $this->testPatternPath,
        ])
        ->expectsQuestion('Database file already exists. Do you want to overwrite it?', 'no')
        ->assertExitCode(0);
        
        // Check file wasn't modified
        $this->assertSame($originalContent, File::get($this->testDbPath), 'File should not be modified when answering no');
        
        // Run with force flag
        try {
            $this->artisan('citadel:compile-regex', [
                '--path' => $this->testDbPath,
                '--patterns' => $this->testPatternPath,
                '--force' => true,
            ])->assertExitCode(0);
            
            // File should be modified
            $this->assertNotSame($originalContent, File::get($this->testDbPath), 'File should be modified when using --force');
        } catch (\Throwable $e) {
            // Only catch library not found exceptions
            if (stripos($e->getMessage(), 'library not found') !== false) {
                $this->markTestSkipped('VectorScan library not found, skipping verification part.');
            } else {
                throw $e;
            }
        }
    }
}