<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\BanType;

class CitadelApiController
{
    /**
     * The data store instance.
     */
    protected DataStore $dataStore;

    /**
     * Create a new controller instance.
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Ban an IP address or fingerprint.
     */
    public function ban(Request $request): JsonResponse
    {
        // Validate the request
        $validator = Validator::make($request->all(), [
            'identifier' => 'required|string',
            'type' => 'nullable|string|in:ip,fingerprint,auto',
            'duration' => 'nullable|integer|min:1',
            'reason' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        // Get validated data
        $identifier = $request->input('identifier');
        $typeString = $request->input('type', 'auto');
        $duration = $request->input('duration');
        $reason = $request->input('reason', 'Manual ban via API');

        // Resolve ban type using our enum
        $banType = $typeString === 'auto'
            ? BanType::tryFrom('auto', true, $identifier) // Auto-detect based on identifier
            : BanType::tryFrom($typeString);

        // Validate the type
        if ($banType === null) {
            return response()->json([
                'status' => 'error',
                'message' => "Invalid identifier type: {$typeString}",
                'valid_types' => BanType::getValues(),
            ], 400);
        }

        // Generate ban key
        $key = $this->generateBanKey($identifier, $banType->value);

        // Create ban record
        $banData = [
            'timestamp' => now()->timestamp,
            'reason' => $reason,
            'type' => $banType->value,
            'via' => 'api',
        ];

        // Store ban record
        if ($duration !== null) {
            $this->dataStore->setValue($key, $banData, (int) $duration);

            return response()->json([
                'status' => 'success',
                'message' => "Banned {$banType->value} '{$identifier}' for {$duration} seconds",
                'data' => [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'duration' => $duration,
                    'reason' => $reason,
                    'timestamp' => now()->timestamp,
                ],
            ]);
        } else {
            // Use a very long TTL for permanent ban (10 years)
            $this->dataStore->setValue($key, $banData, 10 * 365 * 24 * 60 * 60);

            return response()->json([
                'status' => 'success',
                'message' => "Permanently banned {$banType->value} '{$identifier}'",
                'data' => [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'duration' => 'permanent',
                    'reason' => $reason,
                    'timestamp' => now()->timestamp,
                ],
            ]);
        }
    }

    /**
     * Unban an IP address or fingerprint.
     */
    public function unban(Request $request): JsonResponse
    {
        // Validate the request
        $validator = Validator::make($request->all(), [
            'identifier' => 'required|string',
            'type' => 'nullable|string|in:ip,fingerprint,auto',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        // Get validated data
        $identifier = $request->input('identifier');
        $typeString = $request->input('type', 'auto');

        // Resolve ban type using our enum
        $banType = $typeString === 'auto'
            ? BanType::tryFrom('auto', true, $identifier) // Auto-detect based on identifier
            : BanType::tryFrom($typeString);

        // Validate the type
        if ($banType === null) {
            return response()->json([
                'status' => 'error',
                'message' => "Invalid identifier type: {$typeString}",
                'valid_types' => BanType::getValues(),
            ], 400);
        }

        // Generate ban key
        $key = $this->generateBanKey($identifier, $banType->value);

        // Check if the ban exists
        $banData = $this->dataStore->getValue($key);

        if ($banData === null) {
            return response()->json([
                'status' => 'error',
                'message' => "No active ban found for {$banType->value} '{$identifier}'",
            ], 404);
        }

        // Remove the ban
        $success = $this->dataStore->removeValue($key);

        if ($success) {
            return response()->json([
                'status' => 'success',
                'message' => "Successfully unbanned {$banType->value} '{$identifier}'",
                'data' => [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'previous_ban' => $banData,
                ],
            ]);
        } else {
            return response()->json([
                'status' => 'error',
                'message' => "Failed to unban {$banType->value} '{$identifier}'",
            ], 500);
        }
    }

    /**
     * Generate a ban key for the identifier.
     */
    protected function generateBanKey(string $identifier, string $type): string
    {
        $safeIdentifier = Str::slug($identifier);
        $prefix = Config::get(CitadelConfig::KEY_BAN.'.cache_key', 'ban');

        return "{$prefix}:{$type}:{$safeIdentifier}";
    }
}
