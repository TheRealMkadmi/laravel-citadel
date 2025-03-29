<?php

namespace Workbench\App\Providers;

use Illuminate\Support\ServiceProvider;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class WorkbenchServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Register ArrayDataStore as the default implementation for DataStore
        $this->app->singleton(DataStore::class, function ($app) {
            return new ArrayDataStore();
        });
        
        // Configure settings for testing
        config([
            CitadelConfig::KEY_CACHE_DRIVER => ArrayDataStore::STORE_IDENTIFIER,
            CitadelConfig::KEY_CACHE_PREFIX => 'citadel:',
            CitadelConfig::KEY_CACHE_DEFAULT_TTL => 3600,
            CitadelConfig::KEY_BURSTINESS_TTL_BUFFER_MULTIPLIER => 2,
        ]);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Any additional bootstrapping for the workbench environment
    }
}
