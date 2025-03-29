<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Enums;

enum ResponseType: string
{
    case TEXT = 'text';
    case JSON = 'json';
    case VIEW = 'view';
    case REDIRECT = 'redirect';

    /**
     * Get the default response type.
     */
    public static function getDefault(): self
    {
        return self::TEXT;
    }

    /**
     * Create from string value with fallback to default.
     */
    public static function fromString(string $value): self
    {
        return match (strtolower($value)) {
            'text', 'plain' => self::TEXT,
            'json', 'api' => self::JSON,
            'view', 'html', 'blade' => self::VIEW,
            'redirect', 'redir' => self::REDIRECT,
            default => self::getDefault(),
        };
    }

    /**
     * Get a human-readable description of this response type.
     */
    public function description(): string
    {
        return match ($this) {
            self::TEXT => 'Plain text response',
            self::JSON => 'JSON response (for APIs)',
            self::VIEW => 'Blade view render',
            self::REDIRECT => 'Redirect to another URL',
        };
    }
}
