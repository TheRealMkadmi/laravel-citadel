<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Enums;

enum BanType: string
{
    case IP = 'ip';
    case FINGERPRINT = 'fingerprint';

    /**
     * Get all valid ban types as an array.
     */
    public static function getValues(): array
    {
        return [
            self::IP->value,
            self::FINGERPRINT->value,
        ];
    }

    /**
     * Attempt to create from a string value.
     *
     * @param  string  $value  The input string
     * @param  bool  $autoDetect  Whether to auto-detect the type from input if not recognized
     * @param  string|null  $input  Original input for auto-detection
     * @return self|null The matching enum case or null
     */
    public static function tryFrom(string $value, bool $autoDetect = false, ?string $input = null): ?self
    {
        // Direct match
        $directMatch = self::tryFrom($value);
        if ($directMatch !== null) {
            return $directMatch;
        }

        // Auto-detect if requested
        if ($autoDetect && $input !== null) {
            // If it looks like an IP address, treat it as an IP
            if (filter_var($input, FILTER_VALIDATE_IP)) {
                return self::IP;
            }

            // Otherwise assume it's a fingerprint
            return self::FINGERPRINT;
        }

        return null;
    }
}
