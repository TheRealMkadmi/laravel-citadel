<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Enums;

/**
 * Defines the fundamental types of analyzers based on their behavior and impact
 */
enum AnalyzerType: string {    
    /**
     * Analyzers that can block requests based on their score
     */
    case BLOCKING = "blocking";
    
    /**
     * Analyzers that only monitor and score behavior but don't block
     */
    case MONITORING = "monitoring";

    /**
     * Get all possible enum values as strings
     */
    public static function getValues(): array {
        return [
            self::BLOCKING->value,
            self::MONITORING->value,
        ];
    }

    /**
     * Create enum from string value with fallback
     */
    public static function fromString(string $value): self {
        return match (strtolower($value)) {
            'blocking' => self::BLOCKING,
            'monitoring' => self::MONITORING,
            default => self::MONITORING,
        };
    }
}