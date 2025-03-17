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
];
