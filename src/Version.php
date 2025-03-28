<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel;

/**
 * Version information for Laravel Citadel.
 * 
 * This class centralizes version information and provides methods
 * for version comparison and features availability.
 */
final class Version
{
    /**
     * Current version of Laravel Citadel.
     */
    public const VERSION = '1.1.0';
    
    /**
     * Get the current package version.
     */
    public static function get(): string
    {
        return self::VERSION;
    }
    
    /**
     * Check if current version is at least the specified version.
     */
    public static function isAtLeast(string $version): bool
    {
        return version_compare(self::VERSION, $version, '>=');
    }
    
    /**
     * Check if a specific feature is available in the current version.
     */
    public static function hasFeature(string $featureName): bool
    {
        $featureVersions = [
            'enums' => '1.1.0',
            'config-constants' => '1.1.0',
            'passive-monitoring' => '1.0.0',
            'geofencing' => '1.0.0',
            'api' => '1.0.0',
        ];
        
        if (!isset($featureVersions[$featureName])) {
            return false;
        }
        
        return self::isAtLeast($featureVersions[$featureName]);
    }
}