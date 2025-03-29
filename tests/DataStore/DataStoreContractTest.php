<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

/**
 * Tests to ensure DataStore implementations adhere to the contract.
 */
class DataStoreContractTest extends TestCase
{
    protected DataStore $dataStore;

    /**
     * Test keys and values
     */
    protected const TEST_KEY = 'test-key';

    protected const TEST_VALUE = 'test-value';

    protected const TEST_TTL = 3600;

    protected function setUp(): void
    {
        parent::setUp();

        // Use ArrayDataStore for contract tests as it's the simplest implementation
        $this->app->singleton(DataStore::class, ArrayDataStore::class);
        $this->dataStore = $this->app->make(DataStore::class);
    }

    #[Test]
    public function data_store_is_resolvable_from_container()
    {
        $dataStore = app(DataStore::class);
        $this->assertInstanceOf(DataStore::class, $dataStore);
    }

    #[Test]
    public function get_value_returns_null_for_non_existent_keys()
    {
        $result = $this->dataStore->getValue('non-existent-key');
        $this->assertNull($result);
    }

    #[Test]
    public function set_value_returns_true_on_success()
    {
        $result = $this->dataStore->setValue(self::TEST_KEY, self::TEST_VALUE);
        $this->assertTrue($result);
    }

    #[Test]
    public function set_value_with_ttl_stores_correctly()
    {
        $this->dataStore->setValue(self::TEST_KEY, self::TEST_VALUE, self::TEST_TTL);
        $result = $this->dataStore->getValue(self::TEST_KEY);

        $this->assertEquals(self::TEST_VALUE, $result);
    }

    #[Test]
    public function remove_value_returns_true_when_key_exists()
    {
        $keyToRemove = 'key-to-remove';

        $this->dataStore->setValue($keyToRemove, self::TEST_VALUE);
        $result = $this->dataStore->removeValue($keyToRemove);

        $this->assertTrue($result);
    }

    #[Test]
    public function z_add_adds_member_to_sorted_set()
    {
        $key = 'test-sorted-set';
        $score = 1.0;
        $member = 'test-member';

        $result = $this->dataStore->zAdd($key, $score, $member);

        $this->assertNotFalse($result);
    }

    #[Test]
    public function pipeline_executes_multiple_commands()
    {
        $key = 'pipeline-test';

        $results = $this->dataStore->pipeline(function ($pipe) use ($key) {
            $pipe->zadd($key, 1.0, 'member1');
            $pipe->zadd($key, 2.0, 'member2');
        });

        $this->assertIsArray($results);
        $this->assertNotEmpty($results);
    }
}
