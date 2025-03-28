<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use TheRealMkadmi\Citadel\Config\CitadelConfig;

class ApiAuthMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        // Get the API token from config
        $configuredToken = Config::get(CitadelConfig::KEY_API_TOKEN);

        // Check if token is configured
        if (empty($configuredToken)) {
            return response()->json(['error' => 'API authentication not configured'], 500);
        }

        // Get token from request
        $requestToken = $this->getTokenFromRequest($request);

        // Validate token
        if ($requestToken !== $configuredToken) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

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
            return $bearerToken;
        }

        // Try to get from custom X-API-Token header
        $headerToken = $request->header('X-API-Token');
        if ($headerToken) {
            return $headerToken;
        }

        // Try to get from query string or form parameter
        return $request->input('api_token');
    }
}
