<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Enums;

enum GeofencingMode: string
{
    case ALLOW = 'allow';
    case BLOCK = 'block';
    
    /**
     * Get the default geofencing mode.
     */
    public static function getDefault(): self
    {
        return self::BLOCK;
    }
    
    /**
     * Create from string value with fallback to default.
     */
    public static function fromString(string $value): self
    {
        return match(strtolower($value)) {
            'allow', 'allowlist', 'whitelist' => self::ALLOW,
            'block', 'blocklist', 'blacklist' => self::BLOCK,
            default => self::getDefault(),
        };
    }
    
    /**
     * Check if this mode is an allow mode.
     */
    public function isAllowMode(): bool
    {
        return $this === self::ALLOW;
    }
    
    /**
     * Check if this mode is a block mode.
     */
    public function isBlockMode(): bool
    {
        return $this === self::BLOCK;
    }
    
    /**
     * Get a human-readable description of this mode.
     */
    public function description(): string
    {
        return match($this) {
            self::ALLOW => 'Allow listed countries only (block all others)',
            self::BLOCK => 'Block listed countries only (allow all others)',
        };
    }
}