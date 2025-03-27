<?php

// config for TheRealMkadmi\Citadel
return [
    /*
    |--------------------------------------------------------------------------
    | Cookie Settings
    |--------------------------------------------------------------------------
    |
    | Here you can configure the cookie settings for fingerprinting.
    |
    */
    'cookie' => [
        'name' => 'persistentFingerprint_visitor_id',
        'expiration' => 60 * 24 * 30, // 30 days in minutes
        'secure' => true,
        'http_only' => true,
        'same_site' => 'lax',
    ],

    /*
    |--------------------------------------------------------------------------
    | Header Settings
    |--------------------------------------------------------------------------
    |
    | Here you can configure the header name used for fingerprinting.
    |
    */
    'header' => [
        'name' => 'X-Fingerprint',
    ],

    /*
    |--------------------------------------------------------------------------
    | Fingerprinting Features
    |--------------------------------------------------------------------------
    |
    | Enable or disable specific fingerprinting features.
    |
    */
    'features' => [
        'collect_ip' => true,
        'collect_user_agent' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Protection Settings
    |--------------------------------------------------------------------------
    |
    | Configure the overall protection settings including the threshold
    | for blocking requests.
    |
    */
    'threshold' => env('CITADEL_THRESHOLD', 50.0),

    /*
    |--------------------------------------------------------------------------
    | Burstiness Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the timing parameters for the burstiness detection.
    | - min_interval: Minimum time (in milliseconds) between requests
    | - window_size: Time window (in milliseconds) for analyzing request patterns
    |
    */
    'burstiness' => [
        'min_interval' => env('CITADEL_BURSTINESS_MIN_INTERVAL', 5000), // milliseconds
        'window_size' => env('CITADEL_BURSTINESS_WINDOW_SIZE', 60000), // milliseconds (60 seconds)
        'max_requests_per_window' => env('CITADEL_MAX_REQUESTS_PER_WINDOW', 5),
        'excess_request_score' => env('CITADEL_EXCESS_REQUEST_SCORE', 10),
        'burst_penalty_score' => env('CITADEL_BURST_PENALTY_SCORE', 20),
        'max_frequency_score' => env('CITADEL_MAX_FREQUENCY_SCORE', 100),
    ],

    /*
    |--------------------------------------------------------------------------
    | Device Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the device analyzer scoring parameters.
    | - desktop_score: Score to add when a desktop device is detected
    | - bot_score: Score to add when a known bot/automated tool is detected
    |
    */
    'device' => [
        'desktop_score' => env('CITADEL_DEVICE_DESKTOP_SCORE', 15.0),
        'bot_score' => env('CITADEL_DEVICE_BOT_SCORE', 30.0),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Store Configuration
    |--------------------------------------------------------------------------
    |
    | Configure how Citadel's DataStore handles caching.
    |
    | Available options for 'driver':
    | - 'auto': Automatically select the best available driver (Octane > Redis > default)
    | - Any cache driver supported by your Laravel application
    |
    | When using 'auto', the preferences determine which stores are prioritized:
    | - prefer_octane: Whether to use Octane's cache when available
    | - prefer_redis: Whether to use Redis when available
    |
    */
    'cache' => [
        'driver' => env('CITADEL_CACHE_DRIVER', 'auto'),
        'prefer_octane' => env('CITADEL_CACHE_PREFER_OCTANE', true),
        'prefer_redis' => env('CITADEL_CACHE_PREFER_REDIS', true),
        'default_ttl' => env('CITADEL_CACHE_TTL', 3600), // Default TTL in seconds
        'use_forever' => env('CITADEL_CACHE_USE_FOREVER', false), // Whether to store values indefinitely by default
    ],
];
