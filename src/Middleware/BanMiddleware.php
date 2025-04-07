<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class BanMiddleware
{
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
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        Log::debug('BanMiddleware: Processing request', [
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
        ]);

        // Skip check if middleware is disabled
        if (! Config::get(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true)) {
            Log::debug('BanMiddleware: Middleware is disabled, skipping ban checks');
            return $next($request);
        }

        // Check if IP is banned
        $ip = $request->ip();
        $ipBanned = $this->isBanned($ip, 'ip');
        
        if ($ipBanned) {
            Log::warning('BanMiddleware: Rejected banned IP address', [
                'ip' => $ip,
                'path' => $request->path(),
                'method' => $request->method(),
                'user_agent' => $request->userAgent(),
            ]);

            return $this->denyAccess();
        }

        Log::debug('BanMiddleware: IP check passed', ['ip' => $ip]);

        // Check if fingerprint is banned
        $fingerprint = $request->getFingerprint();
        if ($fingerprint) {
            $fingerprintBanned = $this->isBanned($fingerprint, 'fingerprint');
            
            if ($fingerprintBanned) {
                Log::warning('BanMiddleware: Rejected banned fingerprint', [
                    'fingerprint' => $fingerprint,
                    'ip' => $ip,
                    'path' => $request->path(),
                    'method' => $request->method(),
                    'user_agent' => $request->userAgent(),
                ]);

                return $this->denyAccess();
            }
            
            Log::debug('BanMiddleware: Fingerprint check passed', ['fingerprint' => $fingerprint]);
        } else {
            Log::debug('BanMiddleware: No fingerprint available for request, skipping fingerprint check');
        }

        Log::debug('BanMiddleware: All ban checks passed, allowing request', [
            'ip' => $ip,
            'fingerprint' => $fingerprint ?? 'not_available',
        ]);

        return $next($request);
    }

    /**
     * Deny access for banned users.
     */
    protected function denyAccess()
    {
        return $this->blockResponse();
    }

    /**
     * Check if an identifier (IP or fingerprint) is banned.
     */
    protected function isBanned(string $identifier, string $type): bool
    {
        $key = $this->getBanKey($identifier, $type);

        return $this->dataStore->getValue($key) !== null;
    }

    /**
     * Generate a ban key for the identifier.
     */
    protected function getBanKey(string $identifier, string $type): string
    {
        $safeIdentifier = Str::slug($identifier);

        return self::KEY_PREFIX."{$type}:{$safeIdentifier}";
    }

    /**
     * Return a response for banned requests.
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function blockResponse()
    {
        $statusCode = Config::get(CitadelConfig::KEY_BAN_RESPONSE_CODE, 403);
        $message = Config::get(CitadelConfig::KEY_BAN_MESSAGE, 'You have been banned from accessing this site.');

        if (request()->expectsJson()) {
            return response()->json($message, $statusCode);
        }

        return response($message, $statusCode);
    }
}
