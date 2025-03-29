<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

use Illuminate\Support\Facades\Config;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Citadel;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

/**
 * Integration tests for DataStore implementations with ServiceProviders
 */
class DataStoreIntegrationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Force use of ArrayDataStore for all tests
        Config::set(CitadelConfig::KEY_CACHE_DRIVER, ArrayDataStore::STORE_IDENTIFIER);

        // Ensure Redis is not preferred
        Config::set(CitadelConfig::KEY_CACHE.'.prefer_redis', false);

        // Explicitly bind ArrayDataStore to DataStore interface
        $this->app->singleton(DataStore::class, ArrayDataStore::class);

        // Create a clean instance for tests
        $this->app->forgetInstance(DataStore::class);
        $this->app->forgetInstance(ArrayDataStore::class);
    }

    #[Test]
    public function it_resolves_array_data_store_from_container()
    {
        // Verify that the container resolves DataStore to ArrayDataStore
        $dataStore = $this->app->make(DataStore::class);
        $this->assertInstanceOf(ArrayDataStore::class, $dataStore);
    }

    #[Test]
    public function it_uses_config_values_for_cache_settings()
    {
        // Set test config values
        $prefix = 'test-prefix:';
        $ttl = 7200;

        Config::set([
            CitadelConfig::KEY_CACHE_PREFIX => $prefix,
            CitadelConfig::KEY_CACHE_DEFAULT_TTL => $ttl,
        ]);

        // Create a new ArrayDataStore that will use the updated config
        $dataStore = new ArrayDataStore;

        // Use the public accessor methods
        $this->assertEquals($prefix, $dataStore->getPrefix());
        $this->assertEquals($ttl, $dataStore->getDefaultTtl());
    }

    #[Test]
    public function it_integrates_with_citadel_service()
    {
        // Create mock ArrayDataStore instance for testing
        $mockDataStore = Mockery::mock(ArrayDataStore::class)
            ->makePartial();

        // Mock the Cache facade
        $mockCache = Mockery::mock('Illuminate\Contracts\Cache\Repository');
        \Illuminate\Support\Facades\Cache::shouldReceive('store')
            ->with(ArrayDataStore::STORE_IDENTIFIER)
            ->andReturn($mockCache);

        $key = 'integration-test';
        $value = ['test' => 'data'];

        // Set up expectations
        $mockDataStore->shouldReceive('getValue')
            ->once()
            ->with($key)
            ->andReturn($value);

        $mockCache->shouldReceive('put')
            ->once()
            ->withArgs(function ($prefixedKey, $val, $ttl) {
                return str_starts_with($prefixedKey, 'citadel:');
            })
            ->andReturn(true);

        // Override the binding to use our mock implementation
        $this->app->instance(DataStore::class, $mockDataStore);

        // Initialize the mock data store
        $mockDataStore->__construct();

        // Set a key in the data store
        $mockDataStore->setValue($key, $value);

        // Verify the Citadel service can retrieve it via the data store
        $citadel = $this->app->make(Citadel::class);
        $retrievedValue = $citadel->getDataStore()->getValue($key);

        $this->assertEquals($value, $retrievedValue);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
