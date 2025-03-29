<?php

namespace TheRealMkadmi\Citadel\Tests;

use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as Orchestra;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;

class TestCase extends Orchestra
{
    use WithWorkbench;

    protected $enablesPackageDiscoveries = true;

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure we're using Array cache driver for all tests
        Config::set(CitadelConfig::KEY_CACHE_DRIVER, ArrayDataStore::STORE_IDENTIFIER);
        Config::set(CitadelConfig::KEY_CACHE.'.prefer_redis', false);
        Config::set('cache.default', 'array');
    }

    protected function getPackageProviders($app)
    {
        return [
            CitadelServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app)
    {
        // Set up environment to avoid Redis
        $app['config']->set('database.redis.client', null);

        // Configure caching to use array driver
        $app['config']->set('cache.default', 'array');
        $app['config']->set('cache.stores.array', [
            'driver' => 'array',
            'serialize' => false,
        ]);
    }
}
