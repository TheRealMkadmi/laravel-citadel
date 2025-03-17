<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Illuminate\Support\Facades\Log;


class ProtectRouteMiddleware
{
    public function handle($request, \Closure $next)
    {
        if (app()->hasDebugModeEnabled()) {
            Log::info("Middleware is running");
            Log::info($request->getFingerprint());
        }
        return $next($request);
    }
}
