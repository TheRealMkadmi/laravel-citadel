<?php

namespace TheRealMkadmi\Citadel\PatternMatchers;

use Illuminate\Support\Facades\Log;

abstract class AbstractMultiPatternMatcher implements MultiPatternMatcher
{
    /**
     * The pattern strings to match against.
     *
     * @var array<int, string>
     */
    protected array $patterns = [];

    /**
     * Constructor.
     *
     * @param  array  $lines  Array of pattern strings, one per line.
     *                        Lines starting with # are treated as comments and skipped.
     */
    public function __construct(array $lines)
    {
        $this->patterns = collect($lines)
            ->map(fn ($line) => trim($line))
            ->filter(fn ($line) => ! empty($line) && ! str_starts_with($line, '#'))
            ->toArray();
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
     * Default implementation of serialize database.
     * Derived classes that support serialization must override this.
     *
     * @param  string  $filePath  Path where to save the serialized database
     * @return bool Always returns false in the default implementation
     */
    public function serializeDatabase(string $filePath): bool
    {
        Log::debug('serializeDatabase() called on a pattern matcher that does not support serialization');

        return false;
    }

    /**
     * Check if this pattern matcher implementation supports serialization.
     *
     * @return bool Default implementation returns false
     */
    public function supportsSerializedDatabase(): bool
    {
        return false;
    }

    /**
     * Get information about a serialized database file.
     *
     * @param  string  $filePath  Path to the serialized database file
     * @return string|null Default implementation returns null
     */
    public function getSerializedDatabaseInfo(string $filePath): ?string
    {
        Log::debug('getSerializedDatabaseInfo() called on a pattern matcher that does not support serialization');

        return null;
    }

    /**
     * Scan the given content for matches against the loaded patterns.
     *
     * @param  string  $content  The content to scan
     * @return array<int, MultiPatternMatch>
     */
    abstract public function scan(string $content): array;
}
