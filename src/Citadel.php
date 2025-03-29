<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\BanType;

class Citadel
{
    /**
     * Key prefix for bans.
     */
    private const BAN_KEY_PREFIX = 'ban:';

    /**
     * The data store instance.
     */
    protected DataStore $dataStore;

    /**
     * Create a new Citadel instance.
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Get fingerprint from the request.
     *
     * This method implements a cascade of fingerprinting approaches:
     * 1. Get from X-Fingerprint header if present
     * 2. Get from a cookie if present
     * 3. Generate a fingerprint from IP and user agent if needed
     *
     * @param  Request  $request  The HTTP request
     * @return string|null The fingerprint or null if unavailable
     */
    public function getFingerprint(Request $request): ?string
    {
        // Get header name from config
        $headerName = Config::get(CitadelConfig::KEY_HEADER.'.name', 'X-Fingerprint');

        // Check if the custom header is present
        $fingerprint = $request->header($headerName);
        if ($fingerprint) {
            return $fingerprint;
        }

        // Check if the fingerprint cookie is present
        $cookieName = Config::get(CitadelConfig::KEY_COOKIE.'.name', 'persistentFingerprint_visitor_id');
        $fingerprint = $request->cookie($cookieName);
        if ($fingerprint) {
            return $fingerprint;
        }

        // No fingerprint available from headers or cookies,
        // Generate one from available request attributes
        return $this->generateFingerprint($request);
    }

    /**
     * Generate a fingerprint from available request attributes.
     *
     * @param  Request  $request  The HTTP request
     * @return string|null Generated fingerprint or null if insufficient data
     */
    public function generateFingerprint(Request $request): ?string
    {
        $attributes = [];

        // Collect from IP if enabled
        if (Config::get(CitadelConfig::KEY_FEATURES.'.collect_ip', true)) {
            $attributes['ip'] = $request->ip() ?? 'unknown';
        }

        if (Config::get(CitadelConfig::KEY_FEATURES.'.collect_user_agent', true)) {
            $attributes['user_agent'] = $request->userAgent() ?? 'unknown';
        }

        // If we don't have enough data to generate a meaningful fingerprint
        if (count($attributes) < 1) {
            return null;
        }

        // Generate a consistent hash of collected attributes
        $fingerprint = hash('sha256', json_encode($attributes));

        return $fingerprint;
    }

    /**
     * Ban an IP address.
     *
     * @param  string  $ip  The IP address to ban
     * @param  int|null  $duration  Duration in seconds (null for permanent)
     * @param  string  $reason  Reason for the ban
     * @return bool Whether the ban was successful
     */
    public function banIp(string $ip, ?int $duration = null, string $reason = 'Manual ban'): bool
    {
        return $this->ban($ip, BanType::IP, $duration, $reason);
    }

    /**
     * Ban a fingerprint.
     *
     * @param  string  $fingerprint  The fingerprint to ban
     * @param  int|null  $duration  Duration in seconds (null for permanent)
     * @param  string  $reason  Reason for the ban
     * @return bool Whether the ban was successful
     */
    public function banFingerprint(string $fingerprint, ?int $duration = null, string $reason = 'Manual ban'): bool
    {
        return $this->ban($fingerprint, BanType::FINGERPRINT, $duration, $reason);
    }

    /**
     * Ban an identifier.
     *
     * @param  string  $identifier  The identifier to ban (IP or fingerprint)
     * @param  BanType  $type  The type of identifier
     * @param  int|null  $duration  Duration in seconds (null for permanent)
     * @param  string  $reason  Reason for the ban
     * @return bool Whether the ban was successful
     */
    public function ban(string $identifier, BanType $type, ?int $duration = null, string $reason = 'Manual ban'): bool
    {
        // Generate ban key
        $key = $this->generateBanKey($identifier, $type->value);

        // Create ban record
        $banData = [
            'timestamp' => now()->timestamp,
            'reason' => $reason,
            'type' => $type->value,
        ];

        // Determine TTL
        if ($duration === null) {
            // Default to configuration or very long TTL for permanent bans
            $duration = Config::get(CitadelConfig::KEY_BAN.'.ban_ttl') ??
                       (10 * 365 * 24 * 60 * 60); // 10 years
        }

        // Store the ban
        return $this->dataStore->setValue($key, $banData, $duration);
    }

    /**
     * Unban an identifier.
     *
     * @param  string  $identifier  The identifier to unban
     * @param  BanType  $type  The type of identifier
     * @return bool Whether the unban was successful
     */
    public function unban(string $identifier, BanType $type): bool
    {
        // Generate ban key
        $key = $this->generateBanKey($identifier, $type->value);

        // Remove the ban
        return $this->dataStore->removeValue($key);
    }

    /**
     * Check if an identifier is banned.
     *
     * @param  string  $identifier  The identifier to check
     * @param  BanType  $type  The type of identifier
     * @return bool Whether the identifier is banned
     */
    public function isBanned(string $identifier, BanType $type): bool
    {
        // Generate ban key
        $key = $this->generateBanKey($identifier, $type->value);

        // Check if ban exists
        return $this->dataStore->getValue($key) !== null;
    }

    /**
     * Get ban details for an identifier.
     *
     * @param  string  $identifier  The identifier to check
     * @param  BanType  $type  The type of identifier
     * @return array|null Ban details or null if not banned
     */
    public function getBan(string $identifier, BanType $type): ?array
    {
        // Generate ban key
        $key = $this->generateBanKey($identifier, $type->value);

        // Get ban details
        return $this->dataStore->getValue($key);
    }

    /**
     * Generate a ban key for an identifier.
     *
     * @param  string  $identifier  The identifier (IP or fingerprint)
     * @param  string  $type  The type of identifier
     * @return string The ban key
     */
    protected function generateBanKey(string $identifier, string $type): string
    {
        $safeIdentifier = Str::slug($identifier);

        return self::BAN_KEY_PREFIX."{$type}:{$safeIdentifier}";
    }
    
    /**
     * Get the data store instance.
     *
     * @return DataStore The data store instance
     */
    public function getDataStore(): DataStore
    {
        return $this->dataStore;
    }
}
