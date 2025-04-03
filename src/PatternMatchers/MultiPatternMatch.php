<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers;

final class MultiPatternMatch
{
    public int $id;

    public int $from;

    public int $to;

    public int $flags;

    public string $match;

    public string $originalPattern;

    public function __construct(int $id, int $from, int $to, int $flags, string $matchedSubstring, string $originalPattern)
    {
        $this->id = $id;
        $this->from = $from;
        $this->to = $to;
        $this->flags = $flags;
        $this->match = $matchedSubstring;
        $this->originalPattern = $originalPattern;
    }
}
