<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Citadel;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

/**
 * Integration tests for DataStore implementations with actual cache system
 */
class DataStoreIntegrationTest extends TestCase
{
    protected ArrayDataStore $dataStore;

    protected string $testPrefix = 'integration_test:';

    protected function setUp(): void
    {
        parent::setUp();

        // Configure for testing
        Config::set(CitadelConfig::KEY_CACHE_DRIVER, ArrayDataStore::STORE_IDENTIFIER);
        Config::set(CitadelConfig::KEY_CACHE_PREFIX, $this->testPrefix);
        Config::set(CitadelConfig::KEY_CACHE.'.prefer_redis', false);

        // Ensure we have a clean cache for testing
        Cache::store(ArrayDataStore::STORE_IDENTIFIER)->flush();

        // Explicitly bind ArrayDataStore to DataStore interface
        $this->app->singleton(DataStore::class, ArrayDataStore::class);

        // Create a clean instance for tests
        $this->app->forgetInstance(DataStore::class);
        $this->app->forgetInstance(ArrayDataStore::class);

        // Create a fresh datastore instance
        $this->dataStore = $this->app->make(DataStore::class);
    }

    #[Test]
    public function it_integrates_with_laravel_cache_system()
    {
        $key = 'cache-integration';
        $value = 'test-value';
        $prefixedKey = $this->testPrefix.$key;

        // Set a value through the DataStore
        $this->dataStore->setValue($key, $value);

        // Check that we can access it directly through Laravel's cache
        $this->assertEquals($value, Cache::store(ArrayDataStore::STORE_IDENTIFIER)->get($prefixedKey));

        // Now update it directly through Laravel's cache
        $newValue = 'updated-value';
        Cache::store(ArrayDataStore::STORE_IDENTIFIER)->put($prefixedKey, $newValue, 60);

        // Check that it's updated in the DataStore
        $this->assertEquals($newValue, $this->dataStore->getValue($key));

        // Now remove it through Laravel's cache
        Cache::store(ArrayDataStore::STORE_IDENTIFIER)->forget($prefixedKey);

        // Check that it's gone from the DataStore
        $this->assertNull($this->dataStore->getValue($key));
    }

    #[Test]
    public function it_maintains_sorted_sets_correctly()
    {
        $key = 'sorted-set-integration';
        $prefixedKey = $this->testPrefix.$key;

        // Add some members to a sorted set
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');

        // Verify the data structure was stored correctly in cache
        $cachedSet = Cache::store(ArrayDataStore::STORE_IDENTIFIER)->get($prefixedKey);
        $this->assertIsArray($cachedSet);
        $this->assertEquals(1.0, $cachedSet['member1']);
        $this->assertEquals(2.0, $cachedSet['member2']);

        // Modify it directly in the cache
        $cachedSet['member3'] = 3.0;
        Cache::store(ArrayDataStore::STORE_IDENTIFIER)->put($prefixedKey, $cachedSet, 60);

        // Check that DataStore sees the change
        $members = $this->dataStore->zRange($key, 0, -1, true);
        $this->assertCount(3, $members);
        $this->assertEquals(3.0, $members['member3']);
    }

    #[Test]
    public function it_integrates_with_citadel_service()
    {
        $key = 'citadel-integration';
        $value = ['test' => 'data'];

        // Get the Citadel service
        $citadel = $this->app->make(Citadel::class);

        // Set a value using the DataStore from Citadel
        $citadel->getDataStore()->setValue($key, $value);

        // Retrieve it using our direct DataStore instance
        $retrievedValue = $this->dataStore->getValue($key);
        $this->assertEquals($value, $retrievedValue);

        // And vice versa - set using our instance, retrieve using Citadel
        $newKey = 'citadel-integration-2';
        $newValue = ['more' => 'data'];
        $this->dataStore->setValue($newKey, $newValue);
        $this->assertEquals($newValue, $citadel->getDataStore()->getValue($newKey));
    }

    #[Test]
    public function it_persists_data_between_requests()
    {
        $key = 'persistence-test';
        $value = 'persistent-value';

        // Store the value
        $this->dataStore->setValue($key, $value);

        // Create a fresh instance as if in a new request
        $newDataStore = new ArrayDataStore;

        // The value should still be accessible
        $this->assertEquals($value, $newDataStore->getValue($key));

        // Clean up
        $newDataStore->removeValue($key);
    }

    #[Test]
    public function it_handles_complex_pipeline_operations()
    {
        $key = 'complex-pipeline';

        // Setup initial data
        $this->dataStore->setValue($key.':counter', 0);

        // Run a complex pipeline
        $results = $this->dataStore->pipeline(function ($pipe) use ($key) {
            // Add some sorted set entries
            $pipe->zadd($key, 1.0, 'item1');
            $pipe->zadd($key, 2.0, 'item2');
            $pipe->zadd($key, 3.0, 'item3');

            // Check the count
            $pipe->zcard($key);

            // Get the range with scores
            $pipe->zrange($key, 0, -1, true);

            // Remove a range
            $pipe->zremrangebyscore($key, 1.0, 2.0);

            // Set TTL
            $pipe->expire($key, 3600);
        });

        // Verify results
        $this->assertEquals(1, $results[0]); // First zadd
        $this->assertEquals(1, $results[1]); // Second zadd
        $this->assertEquals(1, $results[2]); // Third zadd
        $this->assertEquals(3, $results[3]); // zcard

        // Verify that complex operations worked as expected
        $this->assertIsArray($results[4]); // zrange result
        $this->assertEquals(3, count($results[4])); // Should have all 3 members

        $this->assertEquals(2, $results[5]); // zremrangebyscore should have removed 2 items
        $this->assertTrue($results[6]); // expire should return true

        // Verify the final state directly
        $remainingMembers = $this->dataStore->zRange($key, 0, -1);
        $this->assertEquals(['item3'], $remainingMembers);
    }

    protected function tearDown(): void
    {
        // Clean up all test keys
        $testKeys = [
            'cache-integration',
            'sorted-set-integration',
            'citadel-integration',
            'citadel-integration-2',
            'persistence-test',
            'complex-pipeline',
            'complex-pipeline:counter',
        ];

        foreach ($testKeys as $key) {
            $this->dataStore->removeValue($key);
        }

        parent::tearDown();
    }
}
