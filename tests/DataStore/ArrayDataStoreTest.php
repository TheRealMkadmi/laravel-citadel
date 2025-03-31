<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class ArrayDataStoreTest extends TestCase
{
    protected ArrayDataStore $dataStore;
    protected string $prefix;

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure we're using a consistent prefix for our tests
        $this->prefix = 'citadel:';
        Config::set(CitadelConfig::KEY_CACHE_PREFIX, $this->prefix);
        
        // Initialize a real ArrayDataStore instance using Laravel's array cache driver
        $this->dataStore = new ArrayDataStore();
    }

    #[Test]
    public function it_can_set_and_get_values()
    {
        $key = 'test-key';
        $value = 'test-value';

        // Set a value and verify it was stored successfully
        $this->assertTrue($this->dataStore->setValue($key, $value));
        
        // Get the value and verify it matches what we stored
        $result = $this->dataStore->getValue($key);
        $this->assertEquals($value, $result);

        // Test with different data types
        $arrayValue = ['name' => 'John', 'age' => 30];
        $this->dataStore->setValue($key, $arrayValue);
        $this->assertEquals($arrayValue, $this->dataStore->getValue($key));

        $objectValue = (object)['name' => 'Jane', 'age' => 25];
        $this->dataStore->setValue($key, $objectValue);
        $this->assertEquals($objectValue, $this->dataStore->getValue($key));
    }

    #[Test]
    public function it_correctly_handles_non_existent_keys()
    {
        $key = 'non-existent-key';
        
        // Should return null for non-existent keys
        $this->assertNull($this->dataStore->getValue($key));
        
        // Should return false when checking if a non-existent key exists
        $this->assertFalse($this->dataStore->hasValue($key));
    }

    #[Test]
    public function it_can_check_if_value_exists()
    {
        $key = 'existing-key';
        $value = 'existing-value';

        $this->dataStore->setValue($key, $value);
        
        // Should return true when checking if an existing key exists
        $this->assertTrue($this->dataStore->hasValue($key));
    }

    #[Test]
    public function it_can_remove_values()
    {
        $key = 'key-to-remove';
        $value = 'value-to-remove';

        // First set a value
        $this->dataStore->setValue($key, $value);
        $this->assertTrue($this->dataStore->hasValue($key));
        
        // Now remove it
        $result = $this->dataStore->removeValue($key);
        
        // Check that removal was successful
        $this->assertTrue($result);
        
        // Verify the value is gone
        $this->assertFalse($this->dataStore->hasValue($key));
        $this->assertNull($this->dataStore->getValue($key));
    }

    #[Test]
    public function it_can_remove_range_by_rank()
    {
        $key = 'rank-removal-set';

        // Add members with scores
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');
        $this->dataStore->zAdd($key, 4.0, 'member4');
        $this->dataStore->zAdd($key, 5.0, 'member5');

        // Test removing middle elements (indexes 1 through 3)
        $removed = $this->dataStore->zRemRangeByRank($key, 1, 3);
        $this->assertEquals(3, $removed);
        $this->assertEquals(2, $this->dataStore->zCard($key));
        
        // Check remaining members
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertEquals(['member1', 'member5'], $members);

        // Reset the set
        $this->dataStore->removeValue($key);
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');
        
        // Test removing with negative indices
        $removed = $this->dataStore->zRemRangeByRank($key, -2, -1);
        $this->assertEquals(2, $removed);
        $this->assertEquals(1, $this->dataStore->zCard($key));
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertEquals(['member1'], $members);
    }

    #[Test]
    public function it_handles_empty_set_in_range_removal()
    {
        $key = 'empty-set';

        // Try to remove from empty set
        $removed = $this->dataStore->zRemRangeByRank($key, 0, 1);
        $this->assertEquals(0, $removed);
        $this->assertEquals(0, $this->dataStore->zCard($key));
    }

    #[Test]
    public function it_handles_invalid_range_in_removal()
    {
        $key = 'invalid-range-set';

        // Add test data
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');

        // Test start > stop
        $removed = $this->dataStore->zRemRangeByRank($key, 2, 1);
        $this->assertEquals(0, $removed);
        $this->assertEquals(3, $this->dataStore->zCard($key));

        // Test out of bounds range
        $removed = $this->dataStore->zRemRangeByRank($key, 10, 20);
        $this->assertEquals(0, $removed);
        $this->assertEquals(3, $this->dataStore->zCard($key));
    }

    #[Test]
    public function it_can_remove_all_elements_by_rank()
    {
        $key = 'remove-all-set';

        // Add test data
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');

        // Remove all elements
        $removed = $this->dataStore->zRemRangeByRank($key, 0, -1);
        $this->assertEquals(3, $removed);
        $this->assertEquals(0, $this->dataStore->zCard($key));
        $this->assertFalse($this->dataStore->hasValue($key));
    }

    #[Test]
    public function it_maintains_order_after_partial_removal()
    {
        $key = 'order-test-set';

        // Add members with non-sequential scores
        $this->dataStore->zAdd($key, 10.0, 'member1');
        $this->dataStore->zAdd($key, 5.0, 'member2');
        $this->dataStore->zAdd($key, 15.0, 'member3');
        $this->dataStore->zAdd($key, 1.0, 'member4');
        $this->dataStore->zAdd($key, 20.0, 'member5');

        // Remove middle elements
        $removed = $this->dataStore->zRemRangeByRank($key, 1, 3);
        $this->assertEquals(3, $removed);

        // Check remaining elements are in correct order
        $membersWithScores = $this->dataStore->zRange($key, 0, -1, true);
        $this->assertCount(2, $membersWithScores);
        $this->assertEquals(1.0, $membersWithScores['member4']);
        $this->assertEquals(20.0, $membersWithScores['member5']);
    }

    #[Test]
    public function it_can_work_with_sorted_sets()
    {
        $key = 'test-sorted-set';

        // Add members with scores
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');

        // Test zCard returns the correct count
        $this->assertEquals(3, $this->dataStore->zCard($key));

        // Test zRange returns members in correct order
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertCount(3, $members);
        $this->assertEquals(['member1', 'member2', 'member3'], $members);

        // Test zRange with scores
        $membersWithScores = $this->dataStore->zRange($key, 0, -1, true);
        $this->assertCount(3, $membersWithScores);
        $this->assertEquals(1.0, $membersWithScores['member1']);
        $this->assertEquals(2.0, $membersWithScores['member2']);
        $this->assertEquals(3.0, $membersWithScores['member3']);

        // Test updating an existing member's score
        $this->dataStore->zAdd($key, 4.0, 'member1');
        $membersWithScores = $this->dataStore->zRange($key, 0, -1, true);
        $this->assertEquals(4.0, $membersWithScores['member1']);
        $this->assertEquals(3, $this->dataStore->zCard($key)); // Count should still be 3
    }

    #[Test]
    public function it_can_remove_range_by_score()
    {
        $key = 'range-removal-set';

        // Add members with varying scores
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');
        $this->dataStore->zAdd($key, 4.0, 'member4');
        $this->dataStore->zAdd($key, 5.0, 'member5');

        // Remove members with scores in range [2.0, 4.0]
        $removed = $this->dataStore->zRemRangeByScore($key, 2.0, 4.0);
        
        // Should have removed 3 members
        $this->assertEquals(3, $removed);
        
        // Should have 2 members left
        $this->assertEquals(2, $this->dataStore->zCard($key));
        
        // Check remaining members
        $members = $this->dataStore->zRange($key, 0, -1, true);
        $this->assertCount(2, $members);
        $this->assertArrayHasKey('member1', $members);
        $this->assertArrayHasKey('member5', $members);
    }

    #[Test]
    public function it_can_remove_range_by_score_with_infinity()
    {
        $key = 'infinity-range-set';

        // Add members with varying scores
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');

        // Test removing with -inf to 2.0 (should remove member1 and member2)
        $removed = $this->dataStore->zRemRangeByScore($key, '-inf', 2.0);
        $this->assertEquals(2, $removed);
        $this->assertEquals(1, $this->dataStore->zCard($key));
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertEquals(['member3'], $members);

        // Reset the set
        $this->dataStore->removeValue($key);
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');

        // Test removing with 2.0 to +inf (should remove member2 and member3)
        $removed = $this->dataStore->zRemRangeByScore($key, 2.0, '+inf');
        $this->assertEquals(2, $removed);
        $this->assertEquals(1, $this->dataStore->zCard($key));
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertEquals(['member1'], $members);
    }

    #[Test]
    public function it_can_handle_zrange_with_different_indices()
    {
        $key = 'index-test-set';

        // Add members with scores
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');
        $this->dataStore->zAdd($key, 4.0, 'member4');
        $this->dataStore->zAdd($key, 5.0, 'member5');

        // Test positive indices
        $members = $this->dataStore->zRange($key, 1, 3);
        $this->assertEquals(['member2', 'member3', 'member4'], $members);

        // Test negative indices
        $members = $this->dataStore->zRange($key, -3, -1);
        $this->assertEquals(['member3', 'member4', 'member5'], $members);

        // Test mixed indices
        $members = $this->dataStore->zRange($key, 1, -2);
        $this->assertEquals(['member2', 'member3', 'member4'], $members);
        
        // Test out of bounds
        $members = $this->dataStore->zRange($key, 10, 20);
        $this->assertEmpty($members);
        
        // Test inverted indices
        $members = $this->dataStore->zRange($key, 3, 1);
        $this->assertEmpty($members);
    }

    #[Test]
    public function it_can_execute_commands_in_pipeline()
    {
        $key = 'pipeline-test';

        $results = $this->dataStore->pipeline(function ($pipe) use ($key) {
            $pipe->zadd($key, 1.0, 'member1');
            $pipe->zadd($key, 2.0, 'member2');
            $pipe->zcard($key);
            $pipe->zrange($key, 0, -1, true);
            $pipe->zremrangebyscore($key, 1.0, 1.0);
            $pipe->expire($key, 3600);
        });

        // Check that results array contains expected command results
        $this->assertCount(6, $results);
        $this->assertEquals(1, $results[0]); // zadd result
        $this->assertEquals(1, $results[1]); // zadd result
        $this->assertEquals(2, $results[2]); // zcard result
        $this->assertIsArray($results[3]); // zrange result
        $this->assertEquals(1, $results[4]); // zremrangebyscore result
        $this->assertTrue($results[5]); // expire result

        // Verify final state - should have only member2 left
        $this->assertEquals(1, $this->dataStore->zCard($key));
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertEquals(['member2'], $members);
    }

    #[Test]
    public function it_handles_ttl_correctly()
    {
        $key = 'ttl-test';
        $value = 'test-value';
        $ttl = 3600;

        // Set value with explicit TTL
        $this->dataStore->setValue($key, $value, $ttl);
        
        // Value should exist
        $this->assertTrue($this->dataStore->hasValue($key));
        $this->assertEquals($value, $this->dataStore->getValue($key));
    }
    
    #[Test]
    public function it_handles_ttl_with_forever_setting()
    {
        // Configure to use forever setting
        Config::set(CitadelConfig::KEY_CACHE_USE_FOREVER, true);
        
        $key = 'forever-test';
        $value = 'test-value';
        
        // Set value
        $this->dataStore->setValue($key, $value);
        
        // Value should exist
        $this->assertTrue($this->dataStore->hasValue($key));
        $this->assertEquals($value, $this->dataStore->getValue($key));
        
        // Reset config
        Config::set(CitadelConfig::KEY_CACHE_USE_FOREVER, false);
    }

    #[Test]
    public function it_can_handle_arbitrary_data_types()
    {
        $key = 'data-types-test';
        
        // Test with string
        $this->dataStore->setValue($key, 'string value');
        $this->assertEquals('string value', $this->dataStore->getValue($key));
        
        // Test with integer
        $this->dataStore->setValue($key, 42);
        $this->assertEquals(42, $this->dataStore->getValue($key));
        
        // Test with float
        $this->dataStore->setValue($key, 3.14159);
        $this->assertEquals(3.14159, $this->dataStore->getValue($key));
        
        // Test with boolean
        $this->dataStore->setValue($key, true);
        $this->assertTrue($this->dataStore->getValue($key));
        
        // Test with array
        $array = ['one' => 1, 'two' => 2, 'nested' => ['three' => 3]];
        $this->dataStore->setValue($key, $array);
        $this->assertEquals($array, $this->dataStore->getValue($key));
        
        // Test with object
        $object = (object)['name' => 'Test Object', 'properties' => ['a', 'b', 'c']];
        $this->dataStore->setValue($key, $object);
        $this->assertEquals($object, $this->dataStore->getValue($key));
    }

    protected function tearDown(): void
    {
        // Clear any used keys to prevent test pollution
        $keysToClean = [
            'test-key',
            'existing-key',
            'key-to-remove',
            'test-sorted-set',
            'range-removal-set',
            'infinity-range-set',
            'index-test-set',
            'pipeline-test',
            'ttl-test',
            'forever-test',
            'data-types-test',
            'rank-removal-set',
            'empty-set',
            'invalid-range-set',
            'remove-all-set',
            'order-test-set',
            'pipeline-rank-test'
        ];
        
        foreach ($keysToClean as $key) {
            $this->dataStore->removeValue($key);
        }
        
        parent::tearDown();
    }
}
