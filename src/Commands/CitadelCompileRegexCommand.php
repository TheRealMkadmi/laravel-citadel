<?php

namespace TheRealMkadmi\Citadel\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;

class CitadelCompileRegexCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:compile-regex
                            {--path= : Path to save the compiled database file}
                            {--patterns= : Path to the patterns file (defaults to configuration)}
                            {--force : Force compilation even if the database file already exists}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Compile and serialize patterns for VectorScan pattern matcher';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Starting VectorScan pattern database compilation...');

        // Get output path
        $outputPath = $this->option('path') ?? config('citadel.pattern_matcher.serialized_db_path');

        
        if (! $outputPath) {
            $outputPath = storage_path('app/citadel/vectorscan_patterns.db');
            $this->info("No output path specified, using default: {$outputPath}");
        }

        // Check if file already exists
        if (File::exists($outputPath) && ! $this->option('force')) {
            $this->info("Pattern database already exists at {$outputPath}");

            if (! $this->confirm('Database file already exists. Do you want to overwrite it?')) {
                $this->info('Compilation aborted.');

                return 0;
            }
        }

        // Get patterns file path
        $patternsFilePath = $this->option('patterns') ?? config('citadel.pattern_matcher.patterns_file');

        if (! $patternsFilePath || ! File::exists($patternsFilePath)) {
            $this->error("Pattern file not found: {$patternsFilePath}");

            return 1;
        }

        $this->info("Loading patterns from: {$patternsFilePath}");

        // Load patterns
        $patterns = $this->loadPatterns($patternsFilePath);
        $patternCount = count($patterns);

        if ($patternCount === 0) {
            $this->error('No valid patterns found in patterns file.');

            return 1;
        }

        $this->info("Loaded {$patternCount} patterns.");

        // Ensure output directory exists
        $outputDir = dirname($outputPath);
        if (! File::exists($outputDir)) {
            File::makeDirectory($outputDir, 0755, true);
        }

        // Compile patterns
        $this->info('Compiling patterns with VectorScan...');

        try {
            // Initialize the pattern matcher
            $matcher = new VectorScanMultiPatternMatcher($patterns);

            // Serialize the database
            $this->info('Serializing pattern database...');
            $success = $matcher->serializeDatabase($outputPath);

            if (! $success) {
                $this->error('Failed to serialize pattern database.');

                return 1;
            }

            $info = $matcher->getSerializedDatabaseInfo($outputPath);
            $fileSize = File::size($outputPath);

            $this->info('Pattern database successfully compiled and serialized.');
            $this->info("Output file: {$outputPath}");
            $this->info('File size: '.number_format($fileSize).' bytes');

            if ($info) {
                $this->info("Database info: {$info}");
            }

            return 0;
        } catch (\Exception $e) {
            $this->error('Error compiling pattern database: '.$e->getMessage());
            Log::error('Error in CitadelCompileRegexCommand: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return 1;
        }
    }

    /**
     * Load patterns from a file
     */
    protected function loadPatterns(string $filePath): array
    {
        $content = file_get_contents($filePath);
        $lines = preg_split('/\r\n|\r|\n/', $content);

        return collect($lines)
            ->filter(function ($line) {
                $line = trim($line);

                return ! empty($line) && ! str_starts_with($line, '#');
            })
            ->values()
            ->toArray();
    }
}
