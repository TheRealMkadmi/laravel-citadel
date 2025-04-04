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
}
