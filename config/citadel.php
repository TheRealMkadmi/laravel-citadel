<?php

use TheRealMkadmi\Citadel\Enums\GeofencingMode;

// config for TheRealMkadmi\Citadel
return [
    /*
    |--------------------------------------------------------------------------
    | Version
    |--------------------------------------------------------------------------
    |
    | Current version of Laravel Citadel.
    |
    */
    'version' => '1.1.0',

    /*
    |--------------------------------------------------------------------------
    | Geofencing Settings
    |--------------------------------------------------------------------------
    |
    | Configure geographical restrictions for requests.
    | - enabled: Whether geofencing is enabled
    | - mode: 'allow' (whitelist) or 'block' (blacklist)
    | - countries: Comma-separated ISO-3166-1 alpha-2 country codes to allow or block
    |
    */
    'geofencing' => [
        'enabled' => env('CITADEL_GEOFENCING_ENABLED', false),
        'mode' => env('CITADEL_GEOFENCING_MODE', GeofencingMode::BLOCK->value),
        'countries' => env('CITADEL_GEOFENCING_COUNTRIES', ''), // comma-separated ISO-3166-1 alpha-2 country codes
    ],

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
    | IP Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the IP analyzer settings including weights for different
    | IP characteristics detected through the Incolumitas API.
    |
    | Higher positive values indicate more suspicious IP characteristics
    | Negative values indicate more trusted IP characteristics
    |
    */
    'ip' => [
        'enable_ip_analyzer' => env('CITADEL_ENABLE_IP_ANALYZER', true),

        // Weights for different IP characteristics
        'weights' => [
            'bogon' => env('CITADEL_IP_WEIGHT_BOGON', 80.0),
            'datacenter' => env('CITADEL_IP_WEIGHT_DATACENTER', 30.0),
            'tor' => env('CITADEL_IP_WEIGHT_TOR', 60.0),
            'proxy' => env('CITADEL_IP_WEIGHT_PROXY', 50.0),
            'vpn' => env('CITADEL_IP_WEIGHT_VPN', 40.0),
            'abuser' => env('CITADEL_IP_WEIGHT_ABUSER', 70.0),
            'satellite' => env('CITADEL_IP_WEIGHT_SATELLITE', 10.0),
            'mobile' => env('CITADEL_IP_WEIGHT_MOBILE', -10.0),
            'crawler' => env('CITADEL_IP_WEIGHT_CRAWLER', 20.0),
        ],

        // Country-specific handling
        'country_scores' => [
            'high_risk_countries' => [],
            'high_risk_score' => env('CITADEL_HIGH_RISK_COUNTRY_SCORE', 30.0),
            'trusted_countries' => [],
            'trusted_score' => env('CITADEL_TRUSTED_COUNTRY_SCORE', -15.0),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Burstiness Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the timing parameters and scoring rules for burstiness detection.
    |
    */
    'burstiness' => [
        // Enable or disable burstiness analyzer
        'enable_burstiness_analyzer' => env('CITADEL_ENABLE_BURSTINESS_ANALYZER', true),

        // Basic window and interval settings
        'min_interval' => env('CITADEL_BURSTINESS_MIN_INTERVAL', 5000), // milliseconds
        'window_size' => env('CITADEL_BURSTINESS_WINDOW_SIZE', 60000), // milliseconds (60 seconds)
        'max_requests_per_window' => env('CITADEL_MAX_REQUESTS_PER_WINDOW', 5),
        'extreme_request_threshold' => env('CITADEL_EXTREME_REQUEST_THRESHOLD', 15), // Threshold to trigger max score

        // Scoring parameters
        'excess_request_score' => env('CITADEL_EXCESS_REQUEST_SCORE', 10),
        'burst_penalty_score' => env('CITADEL_BURST_PENALTY_SCORE', 20),
        'max_frequency_score' => env('CITADEL_MAX_FREQUENCY_SCORE', 100),

        // Pattern detection parameters
        'min_samples_for_pattern' => env('CITADEL_MIN_SAMPLES_FOR_PATTERN', 3),
        'pattern_history_size' => env('CITADEL_PATTERN_HISTORY_SIZE', 5),
        'very_regular_threshold' => env('CITADEL_VERY_REGULAR_THRESHOLD', 0.1),
        'somewhat_regular_threshold' => env('CITADEL_SOMEWHAT_REGULAR_THRESHOLD', 0.25),
        'very_regular_score' => env('CITADEL_VERY_REGULAR_SCORE', 30),
        'somewhat_regular_score' => env('CITADEL_SOMEWHAT_REGULAR_SCORE', 15),
        'pattern_multiplier' => env('CITADEL_PATTERN_MULTIPLIER', 5),
        'max_pattern_score' => env('CITADEL_MAX_PATTERN_SCORE', 20),

        // History tracking parameters
        'history_ttl_multiplier' => env('CITADEL_HISTORY_TTL_MULTIPLIER', 6),
        'min_violations_for_penalty' => env('CITADEL_MIN_VIOLATIONS_FOR_PENALTY', 1),
        'max_violation_score' => env('CITADEL_MAX_VIOLATION_SCORE', 50),
        'severe_excess_threshold' => env('CITADEL_SEVERE_EXCESS_THRESHOLD', 10),
        'max_excess_score' => env('CITADEL_MAX_EXCESS_SCORE', 30),
        'excess_multiplier' => env('CITADEL_EXCESS_MULTIPLIER', 2),

        // TTL and key management
        'ttl_buffer_multiplier' => env('CITADEL_TTL_BUFFER_MULTIPLIER', 2),
    ],

    /*
    |--------------------------------------------------------------------------
    | Device Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the device analyzer scoring parameters.
    | Negative scores indicate favorable devices (less likely to be threats)
    | Positive scores indicate suspicious devices (more likely to be threats)
    |
    | - smartphone_score: Score to add when a smartphone is detected (negative = favorable)
    | - tablet_score: Score to add when a tablet is detected
    | - desktop_score: Score to add when a desktop device is detected
    | - bot_score: Score to add when a known bot/automated tool is detected
    | - unknown_score: Score to add when device type cannot be determined
    | - bot_patterns: Array of patterns to detect bots in user agent strings
    |
    */
    'device' => [
        'smartphone_score' => env('CITADEL_DEVICE_SMARTPHONE_SCORE', 0.0),
        'tablet_score' => env('CITADEL_DEVICE_TABLET_SCORE', 0.0),
        'desktop_score' => env('CITADEL_DEVICE_DESKTOP_SCORE', 10.0),
        'bot_score' => env('CITADEL_DEVICE_BOT_SCORE', 100.0),
        'unknown_score' => env('CITADEL_DEVICE_UNKNOWN_SCORE', 20.0),

        // Bot detection patterns
        'bot_patterns' => [
            'bot', 'crawl', 'spider', 'slurp', 'search', 'fetch', 'monitor',
            'scrape', 'extract', 'scan', 'wget', 'curl', 'http', 'python',
            'java/', 'libwww', 'perl', 'phantomjs', 'headless', 'automation',
            'lighthouse', 'pagespeed', 'pingdom', 'gtmetrix',
        ],
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

        // Specific TTLs for different cache types
        'device_detection_ttl' => env('CITADEL_DEVICE_DETECTION_TTL', 86400), // 24 hours
        'fingerprint_ttl' => env('CITADEL_FINGERPRINT_TTL', 604800), // 7 days
        'burst_analysis_ttl' => env('CITADEL_BURST_ANALYSIS_TTL', 3600), // 1 hour
        'ip_analysis_ttl' => env('CITADEL_IP_ANALYSIS_TTL', 7200), // 2 hours

        // Prefix for all cache keys to avoid collisions
        'key_prefix' => env('CITADEL_CACHE_PREFIX', 'citadel:'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Payload Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the payload analyzer settings including pattern detection,
    | scoring rules, and thresholds for malicious payload detection.
    |
    */
    'payload' => [
        'enable_payload_analyzer' => env('CITADEL_ENABLE_PAYLOAD_ANALYZER', true),
        'cache_ttl' => env('CITADEL_PAYLOAD_CACHE_TTL', 3600),
        'max_score' => env('CITADEL_PAYLOAD_MAX_SCORE', 100.0),
        'threat_threshold' => env('CITADEL_PAYLOAD_THREAT_THRESHOLD', 40.0),

        // Request size limits
        'max_size' => env('CITADEL_PAYLOAD_MAX_SIZE', 1048576), // 1MB
        'max_params' => env('CITADEL_PAYLOAD_MAX_PARAMS', 100),

        // Scoring for anomaly detection
        'large_payload_score' => env('CITADEL_PAYLOAD_LARGE_SIZE_SCORE', 20.0),
        'many_params_score' => env('CITADEL_PAYLOAD_MANY_PARAMS_SCORE', 15.0),
        'mismatched_content_type_score' => env('CITADEL_PAYLOAD_MISMATCHED_TYPE_SCORE', 10.0),
        'unusual_headers_score' => env('CITADEL_PAYLOAD_UNUSUAL_HEADERS_SCORE', 15.0),
        'inconsistent_accept_headers_score' => env('CITADEL_PAYLOAD_INCONSISTENT_ACCEPT_SCORE', 10.0),
        'suspicious_request_method_score' => env('CITADEL_PAYLOAD_SUSPICIOUS_METHOD_SCORE', 15.0),
        'repeated_identical_requests_score' => env('CITADEL_PAYLOAD_REPEATED_REQUESTS_SCORE', 15.0),
        'sequential_probing_score' => env('CITADEL_PAYLOAD_SEQUENTIAL_PROBE_SCORE', 20.0),
    ],

    /*
    |--------------------------------------------------------------------------
    | Spamminess Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Configure the spamminess analyzer settings including scoring rules,
    | thresholds, and text analysis parameters.
    |
    */
    'spamminess' => [
        'enable_spamminess_analyzer' => env('CITADEL_ENABLE_SPAMMINESS_ANALYZER', true),
        'max_score' => env('CITADEL_SPAMMINESS_MAX_SCORE', 100.0),

        // Scoring weights for different types of anomalies
        'weights' => [
            'gibberish_text' => env('CITADEL_SPAMMINESS_GIBBERISH_WEIGHT', 25.0),
            'repetitive_content' => env('CITADEL_SPAMMINESS_REPETITIVE_WEIGHT', 10.0),
            'suspicious_entropy' => env('CITADEL_SPAMMINESS_ENTROPY_WEIGHT', 20.0),
            'statistical_anomaly' => env('CITADEL_SPAMMINESS_STATISTICAL_WEIGHT', 30.0),
        ],

        // Text analysis parameters
        'text_analysis' => [
            'min_entropy_threshold' => env('CITADEL_SPAMMINESS_MIN_ENTROPY', 1.0),
            'max_entropy_threshold' => env('CITADEL_SPAMMINESS_MAX_ENTROPY', 4.0),
            'min_field_length' => env('CITADEL_SPAMMINESS_MIN_FIELD_LENGTH', 2),
            'max_repetition_ratio' => env('CITADEL_SPAMMINESS_MAX_REPETITION', 0.4),
            'min_vowel_ratio' => env('CITADEL_SPAMMINESS_MIN_VOWEL_RATIO', 0.1),
            'consonant_sequence_threshold' => env('CITADEL_SPAMMINESS_CONSONANT_SEQ', 4),
            'character_distribution_threshold' => env('CITADEL_SPAMMINESS_CHAR_DIST', 0.7),
            'zipf_deviation_threshold' => env('CITADEL_SPAMMINESS_ZIPF_THRESHOLD', 0.4),
            'statistical_significance_threshold' => env('CITADEL_SPAMMINESS_STAT_THRESHOLD', 0.05),
            'max_correlation_threshold' => env('CITADEL_SPAMMINESS_MAX_CORR', 0.8),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Ban Settings
    |--------------------------------------------------------------------------
    |
    | Configure settings related to the ban feature.
    | - ban_ttl: Default time-to-live for bans in seconds (null = permanent)
    | - cache_key: The key prefix used for storing banned IPs/fingerprints
    |
    */
    'ban' => [
        'ban_ttl' => env('CITADEL_BAN_TTL', null), // null means permanent
        'cache_key' => env('CITADEL_BAN_CACHE_KEY', 'banned'),
        'message' => env('CITADEL_BAN_MESSAGE', 'You have been banned from accessing this site.'),
        'response_code' => env('CITADEL_BAN_RESPONSE_CODE', 403),
    ],

    /*
    |--------------------------------------------------------------------------
    | API Settings
    |--------------------------------------------------------------------------
    |
    | Configure settings for the Citadel API endpoints.
    | - enabled: Whether API endpoints are enabled
    | - token: Secret token for API authentication (should use a strong, random value)
    | - prefix: Prefix for API routes
    |
    */
    'api' => [
        'enabled' => env('CITADEL_API_ENABLED', false),
        'token' => env('CITADEL_API_TOKEN'),
        'prefix' => env('CITADEL_API_PREFIX', 'api/citadel'),
    ],

    /*
    |--------------------------------------------------------------------------
    | External Resource Analyzer Settings
    |--------------------------------------------------------------------------
    |
    | Control analyzers that make external API calls or use external resources.
    | This allows for globally enabling/disabling external resource usage, which
    | may be useful in development environments or to limit API usage costs.
    |
    */
    'external_analyzers' => [
        'enabled' => env('CITADEL_ENABLE_EXTERNAL_ANALYZERS', true),
        'log_disabled_calls' => env('CITADEL_LOG_DISABLED_EXTERNAL_CALLS', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Pattern Matcher Settings
    |--------------------------------------------------------------------------
    |
    | Configure the pattern matcher implementation and settings.
    | - implementation: The pattern matcher implementation to use ('vectorscan' or other implementations)
    | - patterns_file: The path to the file containing regex patterns
    |
    */
    'pattern_matcher' => [
        'implementation' => env('CITADEL_PATTERN_MATCHER_IMPL', 'vectorscan'),
        'patterns_file' => env('CITADEL_PATTERNS_FILE', __DIR__.'/../data/http-payload-regex.list'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Vectorscan Settings
    |--------------------------------------------------------------------------
    |
    | Configure the Vectorscan library settings.
    | - library_path: The path to the libvectorscan shared library
    |
    */
    'vectorscan' => [
        'library_path' => env('CITADEL_VECTORSCAN_LIBRARY_PATH', null),
    ],
];
