<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\PatternMatchers;

final class MultiPatternMatch
{
    public int $id;

    public int $from;

    public int $to;

    public int $flags;

    public string $matchedSubstring;

    public string $originalPattern;

    public function __construct(int $id, int $from, int $to, int $flags, string $matchedSubstring, string $originalPattern)
    {
        $this->id = $id;
        $this->from = $from;
        $this->to = $to;
        $this->flags = $flags;
        $this->matchedSubstring = $matchedSubstring;
        $this->originalPattern = $originalPattern;
    }
}
