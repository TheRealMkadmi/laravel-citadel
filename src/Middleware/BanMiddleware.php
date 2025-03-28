<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class BanMiddleware
{
    /**
     * The data store instance.
     */
    protected DataStore $dataStore;

    /**
     * The prefix used for ban cache keys.
     */
    protected string $banKeyPrefix;

    /**
     * The message to display when a user is banned.
     */
    protected string $banMessage;

    /**
     * The HTTP status code to return when a user is banned.
     */
    protected int $banResponseCode;

    /**
     * Create a new middleware instance.
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
        $this->banKeyPrefix = config('citadel.cache.key_prefix', 'citadel:').config('citadel.ban.cache_key', 'banned');
        $this->banMessage = config('citadel.ban.message', 'You have been banned from accessing this site.');
        $this->banResponseCode = (int) config('citadel.ban.response_code', 403);
    }

    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Check if the user is banned by IP
        $ipKey = $this->generateBanKey('ip', $request->ip());
        if ($this->dataStore->hasValue($ipKey)) {
            Log::info(trans('citadel::messages.ip_banned', ['ip' => $request->ip()]));

            return response()->json([
                'message' => $this->banMessage,
                'citadel' => true,
                'banned' => true,
            ], $this->banResponseCode);
        }

        // Check if user is banned by fingerprint
        $fingerprint = $request->getFingerprint();
        if ($fingerprint) {
            $fingerprintKey = $this->generateBanKey('fingerprint', $fingerprint);
            if ($this->dataStore->hasValue($fingerprintKey)) {
                Log::info(trans('citadel::messages.fingerprint_banned', ['fingerprint' => $fingerprint]));

                return response()->json([
                    'message' => $this->banMessage,
                    'citadel' => true,
                    'banned' => true,
                ], $this->banResponseCode);
            }
        }

        // User is not banned, allow the request to proceed
        return $next($request);
    }

    /**
     * Generate a cache key for banned items.
     *
     * @param  string  $type  The type of ban (ip or fingerprint)
     * @param  string  $value  The value to check (ip address or fingerprint)
     */
    protected function generateBanKey(string $type, string $value): string
    {
        return "{$this->banKeyPrefix}:{$type}:{$value}";
    }
}
