<?php

namespace TheRealMkadmi\Citadel\PatternMatchers;

abstract class AbstractMultiPatternMatcher implements MultiPatternMatcher
{
    protected array $patterns = [];

    public function __construct(array $lines)
    {
        $this->patterns = collect($lines)
            ->map(fn ($line) => trim($line))
            ->filter(fn ($line) => ! empty($line) && ! str_starts_with($line, '#'))
            ->toArray();
    }

    public function getPatterns(): array
    {
        return $this->patterns;
    }

    abstract public function scan(string $content): array;
}
