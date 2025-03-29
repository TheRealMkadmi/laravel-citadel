<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Config;

/**
 * Class containing configuration key constants for the Citadel package.
 */
class CitadelConfig
{
    /**
     * Root configuration key for all Citadel settings
     */
    public const KEY_ROOT = 'citadel';

    /**
     * Middleware configuration keys
     */
    public const KEY_MIDDLEWARE = 'citadel.middleware';

    public const KEY_MIDDLEWARE_ENABLED = 'citadel.middleware.enabled';

    public const KEY_MIDDLEWARE_ACTIVE_ENABLED = 'citadel.middleware.active_enabled';

    public const KEY_MIDDLEWARE_PASSIVE_ENABLED = 'citadel.middleware.passive_enabled';

    public const KEY_MIDDLEWARE_THRESHOLD_SCORE = 'citadel.middleware.threshold_score';

    public const KEY_MIDDLEWARE_WARNING_THRESHOLD = 'citadel.middleware.warning_threshold';

    public const KEY_MIDDLEWARE_BAN_ENABLED = 'citadel.middleware.ban_enabled';

    public const KEY_MIDDLEWARE_BAN_DURATION = 'citadel.middleware.ban_duration';

    public const KEY_MIDDLEWARE_CACHE_TTL = 'citadel.middleware.cache_ttl';

    /**
     * Response configuration keys
     */
    public const KEY_RESPONSE_TYPE = 'citadel.middleware.block_response.type';

    public const KEY_RESPONSE_CODE = 'citadel.middleware.block_response.code';

    public const KEY_RESPONSE_MESSAGE = 'citadel.middleware.block_response.message';

    public const KEY_RESPONSE_VIEW = 'citadel.middleware.block_response.view';

    /**
     * Cache configuration keys
     */
    public const KEY_CACHE = 'citadel.cache';

    public const KEY_CACHE_DRIVER = 'citadel.cache.driver';

    public const KEY_CACHE_PREFIX = 'citadel.cache.key_prefix';

    public const KEY_CACHE_DEFAULT_TTL = 'citadel.cache.default_ttl';

    public const KEY_CACHE_USE_FOREVER = 'citadel.cache.use_forever';

    /**
     * Analyzer configuration keys
     */
    public const KEY_BURSTINESS = 'citadel.burstiness';

    public const KEY_BURSTINESS_TTL_BUFFER_MULTIPLIER = 'citadel.burstiness.ttl_buffer_multiplier';

    public const KEY_PAYLOAD = 'citadel.payload';

    public const KEY_IP = 'citadel.ip';

    public const KEY_DEVICE = 'citadel.device';

    public const KEY_SPAMMINESS = 'citadel.spamminess';

    /**
     * Ban configuration keys
     */
    public const KEY_BAN = 'citadel.ban';

    public const KEY_BAN_TTL = 'citadel.ban.ban_ttl';

    public const KEY_BAN_CACHE_KEY = 'citadel.ban.cache_key';

    public const KEY_BAN_MESSAGE = 'citadel.ban.message';

    public const KEY_BAN_RESPONSE_CODE = 'citadel.ban.response_code';

    /**
     * API configuration keys
     */
    public const KEY_API = 'citadel.api';

    public const KEY_API_ENABLED = 'citadel.api.enabled';

    public const KEY_API_TOKEN = 'citadel.api.token';

    public const KEY_API_PREFIX = 'citadel.api.prefix';

    /**
     * Geofencing configuration keys
     */
    public const KEY_GEOFENCING = 'citadel.geofencing';

    public const KEY_GEOFENCING_ENABLED = 'citadel.geofencing.enabled';

    public const KEY_GEOFENCING_MODE = 'citadel.geofencing.mode';

    public const KEY_GEOFENCING_COUNTRIES = 'citadel.geofencing.countries';

    /**
     * User identification configuration keys
     */
    public const KEY_HEADER = 'citadel.header';

    public const KEY_HEADER_NAME = 'citadel.header.name';

    public const KEY_COOKIE = 'citadel.cookie';

    public const KEY_COOKIE_NAME = 'citadel.cookie.name';

    /**
     * Features configuration keys
     */
    public const KEY_FEATURES = 'citadel.features';

    public const KEY_FEATURES_COLLECT_IP = 'citadel.features.collect_ip';
    
    public const KEY_FEATURES_COLLECT_USER_AGENT = 'citadel.features.collect_user_agent';
}
