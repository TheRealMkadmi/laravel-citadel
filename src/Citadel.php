<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\BanType;
use TheRealMkadmi\Citadel\Events\BlacklistUpdated;
use TheRealMkadmi\Citadel\IpTree\IpTree;
use Illuminate\Events\Dispatcher;

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


    protected IpTree $tree;
    protected Dispatcher $events;
    protected string $channel;

    /**
     * Create a new Citadel instance.
     */
    public function __construct(DataStore $dataStore, IpTree $tree, Dispatcher $events, string $channel)
    {
        $this->tree = $tree;
        $this->events = $events;
        $this->channel = $channel;
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
        $headerName = Config::get(CitadelConfig::KEY_HEADER . '.name', 'X-Fingerprint');

        // Check if the custom header is present
        $fingerprint = $request->header($headerName);
        if ($fingerprint) {
            Log::debug('Citadel: Retrieved fingerprint from header', [
                'header_name' => $headerName,
                'fingerprint_length' => strlen($fingerprint),
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);

            return $fingerprint;
        }

        // Check if the fingerprint cookie is present
        $cookieName = Config::get(CitadelConfig::KEY_COOKIE . '.name', 'persistentFingerprint_visitor_id');
        $fingerprint = $request->cookie($cookieName);
        if ($fingerprint) {
            Log::debug('Citadel: Retrieved fingerprint from cookie', [
                'cookie_name' => $cookieName,
                'fingerprint_length' => strlen($fingerprint),
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);

            return $fingerprint;
        }

        Log::debug('Citadel: No fingerprint found in header or cookie, attempting to generate one');

        // No fingerprint available from headers or cookies,
        // Generate one from available request attributes
        $generatedFingerprint = $this->generateFingerprint($request);

        if ($generatedFingerprint) {
            Log::info('Citadel: Generated new fingerprint', [
                'fingerprint_length' => strlen($generatedFingerprint),
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);
        } else {
            Log::warning('Citadel: Failed to generate fingerprint - insufficient data', [
                'path' => $request->path(),
                'ip' => $request->ip(),
                'user_agent_present' => $request->userAgent() ? true : false,
            ]);
        }

        return $generatedFingerprint;
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
        $collectedAttributes = [];

        // Collect from IP if enabled
        if (Config::get(CitadelConfig::KEY_FEATURES . '.collect_ip', true)) {
            $ip = $request->ip() ?? 'unknown';
            $attributes['ip'] = $ip;
            $collectedAttributes[] = 'ip';
        }

        if (Config::get(CitadelConfig::KEY_FEATURES . '.collect_user_agent', true)) {
            $userAgent = $request->userAgent() ?? 'unknown';
            $attributes['user_agent'] = $userAgent;
            $collectedAttributes[] = 'user_agent';
        }

        // If we don't have enough data to generate a meaningful fingerprint
        if (count($attributes) < 1) {
            Log::warning('Citadel: Insufficient data to generate fingerprint', [
                'available_attributes' => $collectedAttributes,
                'ip_present' => isset($attributes['ip']) && $attributes['ip'] !== 'unknown',
                'user_agent_present' => isset($attributes['user_agent']) && $attributes['user_agent'] !== 'unknown',
            ]);

            return null;
        }

        Log::debug('Citadel: Generating fingerprint from attributes', [
            'attributes_used' => $collectedAttributes,
            'ip_included' => isset($attributes['ip']),
            'user_agent_included' => isset($attributes['user_agent']),
        ]);

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
        Log::info('Citadel: Banning IP address', [
            'ip' => $ip,
            'duration' => $duration ?? 'permanent',
            'reason' => $reason,
        ]);

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
        Log::info('Citadel: Banning fingerprint', [
            'fingerprint' => $fingerprint,
            'fingerprint_length' => strlen($fingerprint),
            'duration' => $duration ?? 'permanent',
            'reason' => $reason,
        ]);

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

        Log::info('Citadel: Creating ban record', [
            'identifier' => $identifier,
            'type' => $type->value,
            'key' => $key,
            'duration' => $duration ?? 'permanent',
            'reason' => $reason,
        ]);

        // Create ban record
        $banData = [
            'timestamp' => now()->timestamp,
            'reason' => $reason,
            'type' => $type->value,
        ];

        // Determine TTL
        if ($duration === null) {
            // Default to configuration or very long TTL for permanent bans
            $duration = Config::get(CitadelConfig::KEY_BAN . '.ban_ttl') ??
                (10 * 365 * 24 * 60 * 60); // 10 years

            Log::debug('Citadel: Using permanent ban duration', [
                'configured_duration' => $duration,
                'identifier_type' => $type->value,
            ]);
        }

        // Store the ban
        $result = $this->dataStore->setValue($key, $banData, $duration);

        if ($result) {
            Log::info('Citadel: Successfully created ban record', [
                'identifier' => $identifier,
                'type' => $type->value,
                'expires_at' => now()->addSeconds($duration)->toDateTimeString(),
            ]);
        } else {
            Log::error('Citadel: Failed to create ban record', [
                'identifier' => $identifier,
                'type' => $type->value,
                'data_store' => get_class($this->dataStore),
            ]);
        }

        return $result;
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

        Log::info('Citadel: Attempting to unban identifier', [
            'identifier' => $identifier,
            'type' => $type->value,
            'key' => $key,
        ]);

        // Check if ban exists first
        $banExists = $this->dataStore->getValue($key) !== null;

        if (!$banExists) {
            Log::info('Citadel: No existing ban found to remove', [
                'identifier' => $identifier,
                'type' => $type->value,
            ]);

            return false;
        }

        // Remove the ban
        $result = $this->dataStore->removeValue($key);

        if ($result) {
            Log::info('Citadel: Successfully removed ban', [
                'identifier' => $identifier,
                'type' => $type->value,
            ]);
        } else {
            Log::error('Citadel: Failed to remove ban', [
                'identifier' => $identifier,
                'type' => $type->value,
                'data_store' => get_class($this->dataStore),
            ]);
        }

        return $result;
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

        Log::debug('Citadel: Checking if identifier is banned', [
            'identifier' => $identifier,
            'type' => $type->value,
            'key' => $key,
        ]);

        // Check if ban exists
        $banned = $this->dataStore->getValue($key) !== null;

        if ($banned) {
            Log::debug('Citadel: Identifier is banned', [
                'identifier' => $identifier,
                'type' => $type->value,
            ]);
        } else {
            Log::debug('Citadel: Identifier is not banned', [
                'identifier' => $identifier,
                'type' => $type->value,
            ]);
        }

        return $banned;
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

        return self::BAN_KEY_PREFIX . "{$type}:{$safeIdentifier}";
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

    public function addIp(string $ip): void
    {
        $this->tree->insertIp($ip);
        $this->events->dispatch(new BlacklistUpdated('ip', $ip), $this->channel);
    }

    public function addFingerprint(string $fp): void
    {
        $this->events->dispatch(new BlacklistUpdated('fingerprint', $fp), $this->channel);
    }
}
