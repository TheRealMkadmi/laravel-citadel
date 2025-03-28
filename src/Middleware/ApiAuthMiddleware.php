<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class ApiAuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $apiToken = config('citadel.api.token');

        // If token is not set, reject all requests
        if (empty($apiToken)) {
            Log::warning('Citadel API access attempt without configured token');

            return response()->json([
                'success' => false,
                'message' => 'API access is not configured',
            ], 403);
        }

        // Check for token in Authorization header or as a query parameter
        $token = $request->bearerToken() ?? $request->input('token');

        // Validate token using constant-time comparison
        if (! $token || ! hash_equals($apiToken, $token)) {
            Log::warning('Citadel API unauthorized access attempt', [
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access',
            ], 401);
        }

        return $next($request);
    }
}
