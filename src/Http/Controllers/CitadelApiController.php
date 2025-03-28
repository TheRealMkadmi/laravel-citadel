<?php

namespace TheRealMkadmi\Citadel\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class CitadelApiController
{
    /**
     * The data store instance.
     *
     * @var \TheRealMkadmi\Citadel\DataStore\DataStore
     */
    protected DataStore $dataStore;

    /**
     * The prefix used for ban cache keys.
     *
     * @var string
     */
    protected string $banKeyPrefix;

    /**
     * The API token for authentication.
     *
     * @var string
     */
    protected string $apiToken;

    /**
     * Create a new controller instance.
     *
     * @param \TheRealMkadmi\Citadel\DataStore\DataStore $dataStore
     * @return void
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
        $this->banKeyPrefix = config('citadel.cache.key_prefix', 'citadel:') . config('citadel.ban.cache_key', 'banned');
        $this->apiToken = config('citadel.api.token');
    }

    /**
     * Authenticate the request using the API token.
     *
     * @param Request $request
     * @return bool
     */
    protected function authenticate(Request $request): bool
    {
        $token = $request->bearerToken() ?? $request->input('token');
        return $this->apiToken && hash_equals($this->apiToken, $token);
    }

    /**
     * Ban a user by IP address or fingerprint.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function ban(Request $request): JsonResponse
    {
        // Validate authentication
        if (!$this->authenticate($request)) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access'
            ], 401);
        }

        // Validate request
        $validated = $request->validate([
            'identifier' => 'required|string',
            'type' => 'required|in:ip,fingerprint',
            'duration' => 'nullable|integer|min:1'
        ]);

        $identifier = $validated['identifier'];
        $type = $validated['type'];
        $duration = $validated['duration'] ?? null;

        // Validate the identifier based on its type
        if (!$this->validateIdentifier($identifier, $type)) {
            return response()->json([
                'success' => false,
                'message' => "Invalid {$type} format: {$identifier}"
            ], 422);
        }

        // Calculate TTL (null for permanent ban)
        $ttl = $duration ? (int) $duration * 60 : config('citadel.ban.ban_ttl');

        // Generate the ban key and store it
        $banKey = $this->generateBanKey($type, $identifier);
        $this->dataStore->setValue($banKey, true, $ttl);

        // Log the action
        $durationText = $ttl ? "for {$duration} minutes" : "permanently";
        Log::info("Citadel API: User banned by {$type}", [
            'identifier' => $identifier,
            'duration' => $durationText,
            'ban_key' => $banKey,
        ]);

        return response()->json([
            'success' => true,
            'message' => "User {$durationText} banned by {$type}: {$identifier}",
            'ban_key' => $banKey
        ]);
    }

    /**
     * Unban a user by IP address or fingerprint.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function unban(Request $request): JsonResponse
    {
        // Validate authentication
        if (!$this->authenticate($request)) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access'
            ], 401);
        }

        // Validate request
        $validated = $request->validate([
            'identifier' => 'required|string',
            'type' => 'required|in:ip,fingerprint'
        ]);

        $identifier = $validated['identifier'];
        $type = $validated['type'];

        // Generate the ban key
        $banKey = $this->generateBanKey($type, $identifier);

        // Check if the ban exists
        if (!$this->dataStore->hasValue($banKey)) {
            return response()->json([
                'success' => false,
                'message' => "No active ban found for {$type}: {$identifier}"
            ], 404);
        }

        // Remove the ban
        $result = $this->dataStore->removeValue($banKey);

        if ($result) {
            Log::info("Citadel API: User unbanned by {$type}", [
                'identifier' => $identifier,
                'ban_key' => $banKey,
            ]);

            return response()->json([
                'success' => true,
                'message' => "Successfully unbanned {$type}: {$identifier}"
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => "Failed to unban {$type}: {$identifier}"
            ], 500);
        }
    }

    /**
     * Validate the identifier based on its type.
     *
     * @param string $identifier
     * @param string $type
     * @return bool
     */
    protected function validateIdentifier(string $identifier, string $type): bool
    {
        if ($type === 'ip') {
            return filter_var($identifier, FILTER_VALIDATE_IP) !== false;
        } elseif ($type === 'fingerprint') {
            // Simple validation for fingerprint (non-empty string)
            return !empty(trim($identifier));
        }

        return false;
    }

    /**
     * Generate a cache key for banned items.
     *
     * @param string $type The type of ban (ip or fingerprint)
     * @param string $value The value to check (ip address or fingerprint)
     * @return string
     */
    protected function generateBanKey(string $type, string $value): string
    {
        return "{$this->banKeyPrefix}:{$type}:{$value}";
    }
}