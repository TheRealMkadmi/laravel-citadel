<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\PatternMatchers;

interface MultiPatternMatcher
{
    /**
     * Scan the given content for matches against the loaded patterns.
     *
     * @param  string  $content  The content to scan.
     * @return array<int, MultiPatternMatch> An array of matches found in the content.
     */
    public function scan(string $content): array;

    /**
     * Get the patterns used by this matcher.
     *
     * @return array<int, string>
     */
    public function getPatterns(): array;
    
    /**
     * Serialize the compiled pattern database to a file.
     * 
     * @param string $filePath Path where to save the serialized database
     * @return bool True if serialization was successful, false otherwise
     */
    public function serializeDatabase(string $filePath): bool;
    
    /**
     * Check if this pattern matcher implementation supports serialization.
     *
     * @return bool True if serialization is supported, false otherwise
     */
    public function supportsSerializedDatabase(): bool;
    
    /**
     * Get information about a serialized database file.
     * 
     * @param string $filePath Path to the serialized database file
     * @return string|null Database information string or null on error
     */
    public function getSerializedDatabaseInfo(string $filePath): ?string;
}
