<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Enums;

enum AnalyzerType: string {    
    case ACTIVE = "active";
    case PASSIVE = "passive";
    case BOTH = "both";

    /**
     * Analyzer attribute flags
     */
    public const SCANS_PAYLOAD = 'scans_payload';
    public const INVOKES_EXTERNAL_RESOURCE = 'invokes_external_resource';

    public static function getValues(): array {
        return [
            self::ACTIVE->value,
            self::PASSIVE->value,
            self::BOTH->value,
        ];
    }

    public static function fromString(string $value): self {
        return match (strtolower($value)) {
            'active' => self::ACTIVE,
            'passive' => self::PASSIVE,
            'both' => self::BOTH,
            default => self::ACTIVE,
        };
    }
}