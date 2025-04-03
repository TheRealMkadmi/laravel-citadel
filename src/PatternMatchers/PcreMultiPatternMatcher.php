<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers;

use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\Enums\ResponseType;

final class PcreMultiPatternMatcher implements MultiPatternMatcher
{
    /**
     * Constants for PCRE options
     */
    private const PCRE_DEFAULT_OPTIONS = [
        'pattern_delimiter' => '/',      // delimiter used in preg functions
        'pattern_modifiers' => 'si',     // default modifiers: case insensitive, dot matches newlines
        'max_matches_per_pattern' => 10, // maximum matches to return per pattern
        'timeout_ms' => 1000,           // maximum execution time in milliseconds
    ];

    /**
     * Array of regex patterns to match against
     * 
     * @var array<int, string>
     */
    private array $patterns = [];

    /**
     * PCRE options
     * 
     * @var array<string, mixed>
     */
    private array $options;

    /**
     * Stores the original pcre.backtrack_limit value
     */
    private string $originalBacktrackLimit;

    /**
     * Constructor.
     *
     * @param array<int, string> $patterns An array of regex pattern strings.
     * @param array<string, mixed> $options Optional configuration for PCRE matching
     * @throws \RuntimeException if pattern compilation fails
     */
    public function __construct(array $patterns, array $options = [])
    {
        // Ensure patterns array is numerically indexed starting from 0
        $this->patterns = array_values($patterns);
        
        // Merge default options with provided options
        $this->options = array_merge(self::PCRE_DEFAULT_OPTIONS, $options);
        
        // Store original backtrack limit and set new one to prevent regex DoS
        $this->originalBacktrackLimit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '1000000');
        
        // Validate patterns to ensure they're all valid
        $this->validatePatterns();
    }

    /**
     * Destructor to restore original pcre.backtrack_limit
     */
    public function __destruct()
    {
        ini_set('pcre.backtrack_limit', $this->originalBacktrackLimit);
    }

    /**
     * Get the patterns used by this matcher.
     * 
     * @return array<int, string>
     */
    public function getPatterns(): array
    {
        return $this->patterns;
    }

    /**
     * Validate that all patterns can be compiled by PCRE
     * 
     * @return void
     * @throws \RuntimeException if any pattern is invalid
     */
    private function validatePatterns(): void 
    {
        foreach ($this->patterns as $id => $pattern) {
            $delimiter = $this->options['pattern_delimiter'];
            $modifiers = $this->options['pattern_modifiers'];
            $compiledPattern = $delimiter . $pattern . $delimiter . $modifiers;
            
            // Test compile the pattern
            try {
                if (@preg_match($compiledPattern, '') === false) {
                    $error = error_get_last();
                    Log::error("PCRE pattern compilation failed for pattern {$id}: {$pattern}. Error: " . ($error['message'] ?? 'Unknown error'));
                    throw new \RuntimeException("Invalid PCRE pattern: {$pattern}");
                }
            } catch (\Exception $e) {
                Log::error("Exception while compiling pattern {$id}: {$pattern}. Error: {$e->getMessage()}");
                throw new \RuntimeException("Failed to compile PCRE pattern: {$pattern}", 0, $e);
            }
        }
    }

    /**
     * Scan the given content for matches against the loaded patterns.
     *
     * @param string $content The content to scan.
     * @return array<int, MultiPatternMatch>
     * @throws \RuntimeException if scanning fails
     */
    public function scan(string $content): array
    {
        $matches = [];
        
        try {
            // Loop through each pattern and find matches
            foreach ($this->patterns as $id => $pattern) {
                $delimiter = $this->options['pattern_delimiter'];
                $modifiers = $this->options['pattern_modifiers'];
                $compiledPattern = $delimiter . $pattern . $delimiter . $modifiers;
                
                // Match all occurrences
                $matchOffsets = [];
                if (preg_match_all($compiledPattern, $content, $matchedTexts, PREG_OFFSET_CAPTURE) > 0) {
                    // Process only the full pattern matches (index 0 of results)
                    $fullMatches = $matchedTexts[0] ?? [];
                    $maxMatches = $this->options['max_matches_per_pattern'];
                    
                    // Limit the number of matches to avoid excessive processing
                    foreach (array_slice($fullMatches, 0, $maxMatches) as $match) {
                        $matchedSubstring = $match[0];
                        $fromOffset = $match[1];
                        $toOffset = $fromOffset + strlen($matchedSubstring);
                        
                        $matches[] = new MultiPatternMatch(
                            id: $id,
                            from: $fromOffset,
                            to: $toOffset,
                            flags: 0, // PHP PCRE doesn't provide flags like Vectorscan does
                            matchedSubstring: $matchedSubstring,
                            originalPattern: $pattern
                        );
                    }
                }
            }
        } catch (\Exception $e) {
            Log::error("Exception during PCRE scan: {$e->getMessage()}");
            throw new \RuntimeException("Failed during PCRE pattern matching: {$e->getMessage()}", 0, $e);
        }
        
        // Sort matches by position (from lowest to highest offset)
        usort($matches, function (MultiPatternMatch $a, MultiPatternMatch $b) {
            return $a->from <=> $b->from;
        });
        
        return $matches;
    }

    /**
     * Get timeout settings for PCRE matching.
     *
     * @return array<string, int|string>
     */
    public function getSettings(): array
    {
        return $this->options;
    }

    /**
     * Update matcher settings.
     *
     * @param array<string, mixed> $options
     * @return void
     */
    public function updateSettings(array $options): void
    {
        $this->options = array_merge($this->options, $options);
    }
}