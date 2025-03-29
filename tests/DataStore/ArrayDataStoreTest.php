<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class ArrayDataStoreTest extends TestCase
{
    protected ArrayDataStore $dataStore;
    protected $mockCache;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Create mock cache store
        $this->mockCache = Mockery::mock('Illuminate\Contracts\Cache\Repository');
        
        // Mock the Cache facade to return our mock store
        Cache::shouldReceive('store')
            ->with(ArrayDataStore::STORE_IDENTIFIER)
            ->andReturn($this->mockCache);
        
        $this->dataStore = new ArrayDataStore();
    }

    #[Test]
    public function it_can_set_and_get_values()
    {
        $key = 'test-key';
        $prefixedKey = 'citadel:' . $key; // Assuming default prefix is 'citadel:'
        $value = 'test-value';
        
        // Mock behavior for setValue
        $this->mockCache->shouldReceive('put')
            ->once()
            ->with($prefixedKey, $value, Mockery::any())
            ->andReturn(true);
            
        // Mock behavior for getValue
        $this->mockCache->shouldReceive('get')
            ->once()
            ->with($prefixedKey, null)
            ->andReturn($value);
        
        $this->dataStore->setValue($key, $value);
        $result = $this->dataStore->getValue($key);
        
        $this->assertEquals($value, $result);
    }

    #[Test]
    public function it_can_remove_values()
    {
        $key = 'test-key-to-remove';
        $prefixedKey = 'citadel:' . $key;
        $value = 'test-value';
        
        // Mock behavior for hasValue
        $this->mockCache->shouldReceive('has')
            ->with($prefixedKey)
            ->andReturn(true, false);
            
        // Mock behavior for removeValue
        $this->mockCache->shouldReceive('forget')
            ->once()
            ->with($prefixedKey)
            ->andReturn(true);
        
        // Mock setValue behavior
        $this->mockCache->shouldReceive('put')
            ->with($prefixedKey, $value, Mockery::any())
            ->andReturn(true);
            
        // Mock getValue behavior
        $this->mockCache->shouldReceive('get')
            ->with($prefixedKey, null)
            ->andReturn(null);
        
        $this->dataStore->setValue($key, $value);
        $this->assertTrue($this->dataStore->hasValue($key));
        
        $this->dataStore->removeValue($key);
        $this->assertFalse($this->dataStore->hasValue($key));
        $this->assertNull($this->dataStore->getValue($key));
    }

    #[Test]
    public function it_can_work_with_sorted_sets()
    {
        $key = 'test-sorted-set';
        $prefixedKey = 'citadel:' . $key;
        
        // Setup mock data
        $set = [];
        
        // Mock get and put for zAdd operations
        $this->mockCache->shouldReceive('get')
            ->with($prefixedKey, [])
            ->andReturnUsing(function () use (&$set) {
                return $set;
            });
            
        $this->mockCache->shouldReceive('put')
            ->with($prefixedKey, Mockery::any(), Mockery::any())
            ->andReturnUsing(function ($k, $v) use (&$set) {
                $set = $v;
                return true;
            });
        
        // Add members with scores
        $this->dataStore->zAdd($key, 1.0, 'member1');
        $this->dataStore->zAdd($key, 2.0, 'member2');
        $this->dataStore->zAdd($key, 3.0, 'member3');
        
        // Test zCard to get count
        $this->assertEquals(3, $this->dataStore->zCard($key));
        
        // Test zRange to get members by index
        $members = $this->dataStore->zRange($key, 0, -1);
        $this->assertCount(3, $members);
        $this->assertEquals(['member1', 'member2', 'member3'], $members);
        
        // Test zRange with scores
        $membersWithScores = $this->dataStore->zRange($key, 0, -1, true);
        $this->assertCount(3, $membersWithScores);
        $this->assertEquals(1.0, $membersWithScores['member1']);
        $this->assertEquals(2.0, $membersWithScores['member2']);
        $this->assertEquals(3.0, $membersWithScores['member3']);
        
        // Test zRemRangeByScore to remove members with scores in range
        $removed = $this->dataStore->zRemRangeByScore($key, 1.0, 2.0);
        $this->assertEquals(2, $removed);
        $this->assertEquals(1, $this->dataStore->zCard($key));
    }

    #[Test]
    public function it_can_execute_commands_in_pipeline()
    {
        $key = 'test-pipeline';
        $prefixedKey = 'citadel:' . $key;
        
        // Setup mock data
        $set = [];
        
        // Mock get and put for all operations
        $this->mockCache->shouldReceive('get')
            ->with($prefixedKey, [])
            ->andReturnUsing(function () use (&$set) {
                return $set;
            });
            
        $this->mockCache->shouldReceive('put')
            ->with($prefixedKey, Mockery::any(), Mockery::any())
            ->andReturnUsing(function ($k, $v) use (&$set) {
                $set = $v;
                return true;
            });
            
        $this->mockCache->shouldReceive('has')
            ->with($prefixedKey)
            ->andReturn(true);
        
        $results = $this->dataStore->pipeline(function($pipe) use ($key) {
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
        
        // Verify final state
        $this->assertEquals(1, $this->dataStore->zCard($key));
    }

    #[Test] 
    public function it_handles_ttl_correctly()
    {
        $key = 'test-ttl';
        $prefixedKey = 'citadel:' . $key;
        $value = 'test-value';
        $ttl = 3600;
        
        // Mock put behavior
        $this->mockCache->shouldReceive('put')
            ->once()
            ->with($prefixedKey, $value, $ttl)
            ->andReturn(true);
            
        // Mock has behavior
        $this->mockCache->shouldReceive('has')
            ->with($prefixedKey)
            ->andReturn(true);
            
        // Mock get behavior for expire method
        $this->mockCache->shouldReceive('get')
            ->with('citadel:test-expire', null)
            ->andReturn($value);
            
        // Test with explicit TTL
        $this->dataStore->setValue($key, $value, $ttl);
        $this->assertTrue($this->dataStore->hasValue($key));
        
        // Test with expire method
        $key2 = 'test-expire';
        $this->mockCache->shouldReceive('put')
            ->once()
            ->with('citadel:' . $key2, $value, Mockery::any())
            ->andReturn(true);
            
        $this->dataStore->setValue($key2, $value);
        $this->assertTrue($this->dataStore->expire($key2, $ttl));
    }

    #[Test]
    public function it_returns_default_value_when_key_not_found()
    {
        $key = 'non-existent-key';
        $prefixedKey = 'citadel:' . $key;
        $default = 'default-value';
        
        // Mock get behavior
        $this->mockCache->shouldReceive('get')
            ->once()
            ->with($prefixedKey, $default)
            ->andReturn($default);
        
        $result = $this->dataStore->getValue($key, $default);
        
        $this->assertEquals($default, $result);
    }
    
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}