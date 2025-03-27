<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Contracts\DataStore;

class Citadel
{
    /**
     * The shared data store instance.
     *
     * @var \TheRealMkadmi\Citadel\Contracts\DataStore
     */
    protected DataStore $dataStore;

    /**
     * Create a new Citadel instance.
     *
     * @param \TheRealMkadmi\Citadel\Contracts\DataStore $dataStore
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Get the fingerprint from the request.
     * This uses the browser-provided fingerprint without generating a new one.
     *
     * @param Request $request
     * @return string|null
     */
    public function getFingerprint(Request $request): ?string
    {
        // Check for fingerprint in header first (priority)
        $fingerprint = $request->header(config('citadel.header.name'));
        
        // If not in header, check for cookie
        if (!$fingerprint) {
            $fingerprint = $request->cookie(config('citadel.cookie.name'));
        }
        
        // Track the fingerprint if we have one
        if ($fingerprint) {
            $this->trackFingerprint($fingerprint);
        } else {
            Log::debug('Citadel: No fingerprint found in request', [
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'user_agent' => $request->userAgent(),
            ]);
        }
        
        return $fingerprint;
    }

    /**
     * Track a fingerprint in the data store for analytics.
     *
     * @param string $fingerprint
     * @return void
     */
    protected function trackFingerprint(string $fingerprint): void
    {
        $cacheKey = Str::start(
            'fingerprint:' . $fingerprint, 
            config('citadel.cache.key_prefix', 'citadel:')
        );
        
        $ttl = config('citadel.cache.fingerprint_ttl');
        
        // Only update or create fingerprint entry if needed
        if (!$this->dataStore->hasValue($cacheKey)) {
            // First time we've seen this fingerprint
            $this->dataStore->setValue($cacheKey, [
                'first_seen_at' => now()->timestamp,
                'last_seen_at' => now()->timestamp,
                'visits' => 1,
            ], $ttl);
        } else {
            // Update existing fingerprint data
            $data = $this->dataStore->getValue($cacheKey);
            
            // If data is not an array, reset it (handle legacy data)
            if (!is_array($data)) {
                $data = [
                    'first_seen_at' => now()->timestamp,
                    'visits' => 1,
                ];
            } else {
                $data['visits'] = ($data['visits'] ?? 0) + 1;
            }
            
            $data['last_seen_at'] = now()->timestamp;
            
            // Update the record with extended TTL
            $this->dataStore->setValue($cacheKey, $data, $ttl);
        }
    }
}
