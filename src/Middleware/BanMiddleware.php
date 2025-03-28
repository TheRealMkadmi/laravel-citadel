<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class BanMiddleware
{
    /**
     * Configuration keys.
     */
    private const CONFIG_KEY_ACTIVE_ENABLED = 'citadel.middleware.active_enabled';
    private const CONFIG_KEY_BAN_MESSAGE = 'citadel.ban.message';
    private const CONFIG_KEY_BAN_RESPONSE_CODE = 'citadel.ban.response_code';
    
    /**
     * Ban key prefix.
     */
    private const KEY_PREFIX = 'ban:';

    /**
     * The data store instance.
     */
    protected DataStore $dataStore;

    /**
     * Create a new middleware instance.
     *
     * @param DataStore $dataStore
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Skip ban check if active middleware is disabled
        if (!Config::get(self::CONFIG_KEY_ACTIVE_ENABLED, true)) {
            return $next($request);
        }

        // Check if the IP is banned
        $ipBanned = $this->isBanned($request->ip(), 'ip');
        if ($ipBanned) {
            Log::info('Citadel: Access attempt from banned IP', [
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
            ]);
            
            return $this->blockResponse();
        }

        // Check if the fingerprint is banned
        $fingerprint = $request->getFingerprint();
        $fingerprintBanned = $this->isBanned($fingerprint, 'fingerprint');
        if ($fingerprintBanned) {
            Log::info('Citadel: Access attempt from banned fingerprint', [
                'fingerprint' => $fingerprint,
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
            ]);
            
            return $this->blockResponse();
        }

        return $next($request);
    }

    /**
     * Check if an identifier (IP or fingerprint) is banned.
     *
     * @param string $identifier
     * @param string $type
     * @return bool
     */
    protected function isBanned(string $identifier, string $type): bool
    {
        $key = $this->getBanKey($identifier, $type);
        return $this->dataStore->getValue($key) !== null;
    }

    /**
     * Generate a ban key for the identifier.
     *
     * @param string $identifier
     * @param string $type
     * @return string
     */
    protected function getBanKey(string $identifier, string $type): string
    {
        $safeIdentifier = Str::slug($identifier);
        return self::KEY_PREFIX . "{$type}:{$safeIdentifier}";
    }

    /**
     * Return a response for banned requests.
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function blockResponse()
    {
        $statusCode = Config::get(self::CONFIG_KEY_BAN_RESPONSE_CODE, 403);
        $message = Config::get(self::CONFIG_KEY_BAN_MESSAGE, 'You have been banned from accessing this site.');

        if (request()->expectsJson()) {
            return response()->json(['error' => $message], $statusCode);
        }

        return response($message, $statusCode);
    }
}
