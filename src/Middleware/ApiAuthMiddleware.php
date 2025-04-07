<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\Config\CitadelConfig;

class ApiAuthMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        Log::debug('ApiAuthMiddleware: Processing API authentication request', [
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
        ]);

        // Get the API token from config
        $configuredToken = Config::get(CitadelConfig::KEY_API_TOKEN);

        // Check if token is configured
        if (empty($configuredToken)) {
            Log::error('ApiAuthMiddleware: API authentication not configured, missing token in config');

            return response()->json(['error' => 'API authentication not configured'], 500);
        }

        // Get token from request
        $requestToken = $this->getTokenFromRequest($request);

        if (empty($requestToken)) {
            Log::warning('ApiAuthMiddleware: Authentication failed - no token provided', [
                'ip' => $request->ip(),
                'path' => $request->path(),
                'user_agent' => $request->userAgent(),
            ]);

            return response()->json(['error' => 'Unauthorized - no token provided'], 401);
        }

        // Validate token
        if ($requestToken !== $configuredToken) {
            Log::warning('ApiAuthMiddleware: Authentication failed - invalid token', [
                'ip' => $request->ip(),
                'path' => $request->path(),
                'token_length' => strlen($requestToken),
            ]);

            return response()->json(['error' => 'Unauthorized'], 401);
        }

        Log::info('ApiAuthMiddleware: Successful API authentication', [
            'ip' => $request->ip(),
            'path' => $request->path(),
        ]);

        // Token is valid, proceed with request
        return $next($request);
    }

    /**
     * Extract token from request (header, query string, or form data).
     */
    protected function getTokenFromRequest(Request $request): ?string
    {
        // Try to get from Authorization header (Bearer token)
        $bearerToken = $request->bearerToken();
        if ($bearerToken) {
            Log::debug('ApiAuthMiddleware: Found token in Authorization header');

            return $bearerToken;
        }

        // Try to get from custom X-API-Token header
        $headerToken = $request->header('X-API-Token');
        if ($headerToken) {
            Log::debug('ApiAuthMiddleware: Found token in X-API-Token header');

            return $headerToken;
        }

        // Try to get from query string or form parameter
        $queryToken = $request->input('api_token');
        if ($queryToken) {
            Log::debug('ApiAuthMiddleware: Found token in query string or form data');

            return $queryToken;
        }

        Log::debug('ApiAuthMiddleware: No token found in request');

        return null;
    }
}
