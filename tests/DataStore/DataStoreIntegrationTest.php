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
        
        // Ensure we're using ArrayDataStore for tests
        Config::set(CitadelConfig::KEY_CACHE_DRIVER, ArrayDataStore::STORE_IDENTIFIER);
        $this->app->singleton(DataStore::class, ArrayDataStore::class);
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
        
        // Create a testable array data store
        $dataStore = Mockery::mock(ArrayDataStore::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        // Test the prefix is correctly retrieved
        $this->assertEquals($prefix, $dataStore->getPrefix());
        
        // Test the TTL is correctly retrieved
        $this->assertEquals($ttl, $dataStore->getDefaultTtl());
    }

    #[Test]
    public function it_integrates_with_citadel_service()
    {
        // Create a mock DataStore instance
        $dataStoreImplementation = new ArrayDataStore();
        
        // Override the binding to use our implementation
        $this->app->instance(DataStore::class, $dataStoreImplementation);
        
        // Set a key in the data store
        $key = 'integration-test';
        $value = ['test' => 'data'];
        
        $dataStore = $this->app->make(DataStore::class);
        $dataStore->setValue($key, $value);
        
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