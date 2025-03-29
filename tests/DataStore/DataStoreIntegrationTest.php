<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

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
    #[Test]
    public function it_resolves_array_data_store_from_container()
    {
        // Verify that the container resolves DataStore to ArrayDataStore
        $dataStore = app(DataStore::class);
        $this->assertInstanceOf(ArrayDataStore::class, $dataStore);
    }

    #[Test]
    public function it_uses_config_values_for_cache_settings()
    {
        // Set test config values
        $prefix = 'test-prefix:';
        $ttl = 7200;
        
        config([
            CitadelConfig::KEY_CACHE_PREFIX => $prefix,
            CitadelConfig::KEY_CACHE_DEFAULT_TTL => $ttl,
        ]);
        
        // Create new instances that should use the updated config
        $dataStore = new ArrayDataStore();
        
        // Test a protected method via reflection to verify prefix
        $prefixMethod = new \ReflectionMethod($dataStore, 'getPrefix');
        $prefixMethod->setAccessible(true);
        $this->assertEquals($prefix, $prefixMethod->invoke($dataStore));
        
        // Test a protected method via reflection to verify TTL
        $ttlMethod = new \ReflectionMethod($dataStore, 'getDefaultTtl');
        $ttlMethod->setAccessible(true);
        $this->assertEquals($ttl, $ttlMethod->invoke($dataStore));
    }

    #[Test]
    public function it_integrates_with_citadel_service()
    {
        // Set a key in the data store
        $key = 'integration-test';
        $value = ['test' => 'data'];
        
        $dataStore = app(DataStore::class);
        $dataStore->setValue($key, $value);
        
        // Verify the Citadel service can retrieve it via the data store
        $citadel = app(Citadel::class);
        $retrievedValue = $citadel->getDataStore()->getValue($key);
        
        $this->assertEquals($value, $retrievedValue);
    }
}