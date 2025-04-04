<?php

use Illuminate\Support\Facades\Route;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\Http\Controllers\CitadelApiController;



$prefix = config(CitadelConfig::KEY_API_PREFIX, 'api/citadel');
$middlewareGroups = ['api'];

// Add the API auth middleware if a token is configured
if (!empty(config(CitadelConfig::KEY_API_TOKEN))) {
    $middlewareGroups[] = CitadelServiceProvider::MIDDLEWARE_ALIAS_API_AUTH;
} else {
    app('log')->warning('Citadel API is enabled but no API token is configured. This is a security risk.');
}

Route::prefix($prefix)
    ->middleware($middlewareGroups)
    ->group(function () {
        // Ban endpoint
        Route::post('/ban', [CitadelApiController::class, 'ban'])
            ->name(CitadelServiceProvider::ROUTE_NAME_BAN);

        // Unban endpoint
        Route::post('/unban', [CitadelApiController::class, 'unban'])
            ->name(CitadelServiceProvider::ROUTE_NAME_UNBAN);

        // Status endpoint - allows checking if the API is accessible
        Route::get('/status', function () {
            return response()->json([
                'status' => 'ok',
                'version' => config('citadel.version', '1.1.0'),
                'timestamp' => now()->toIso8601String(),
            ]);
        })->name(CitadelServiceProvider::ROUTE_NAME_STATUS);
    });


Log::info('Citadel API routes registered with prefix: ' . $prefix);
Log::info('Citadel API routes middleware groups: ' . implode(', ', $middlewareGroups));
