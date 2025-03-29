<?php

namespace TheRealMkadmi\Citadel\Tests\DataStore;

use Illuminate\Support\Facades\Config;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\AbstractDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class AbstractDataStoreTest extends TestCase
{
    protected $dataStore;

    protected function setUp(): void
    {
        parent::setUp();

        // Create a concrete implementation of the abstract class for testing
        $this->dataStore = Mockery::mock(AbstractDataStore::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
    }

    #[Test]
    public function it_generates_prefixed_key()
    {
        // Mock the getPrefix method to return a known prefix
        $testPrefix = 'test-prefix:';
        $testKey = 'test-key';
        
        $this->dataStore->shouldReceive('getPrefix')
            ->andReturn($testPrefix);

        $result = $this->dataStore->getPrefixedKey($testKey);
        
        $this->assertEquals($testPrefix . $testKey, $result);
    }

    #[Test]
    public function it_returns_proper_default_ttl()
    {
        // Test with default config
        $expectedTtl = 3600;
        Config::set(CitadelConfig::KEY_CACHE_DEFAULT_TTL, $expectedTtl);
        
        $ttl = $this->dataStore->getDefaultTtl();
        
        $this->assertEquals($expectedTtl, $ttl);
    }

    #[Test]
    public function it_calculates_ttl_from_milliseconds()
    {
        $milliseconds = 60000; // 60 seconds in milliseconds
        $bufferMultiplier = 2;
        
        Config::set(CitadelConfig::KEY_BURSTINESS_TTL_BUFFER_MULTIPLIER, $bufferMultiplier);
        
        $ttl = $this->dataStore->calculateTtl($milliseconds);
        
        // Should convert milliseconds to seconds and apply the buffer multiplier
        $expectedTtl = ($milliseconds / 1000) * $bufferMultiplier;
        $this->assertEquals($expectedTtl, $ttl);
    }

    #[Test]
    public function it_determines_when_to_use_forever_cache()
    {
        // Test when TTL is set to 0 or negative
        Config::set(CitadelConfig::KEY_CACHE_DEFAULT_TTL, 0);
        $this->assertTrue($this->dataStore->shouldUseForever());
        
        Config::set(CitadelConfig::KEY_CACHE_DEFAULT_TTL, -1);
        $this->assertTrue($this->dataStore->shouldUseForever());
        
        // Test with positive TTL
        Config::set(CitadelConfig::KEY_CACHE_DEFAULT_TTL, 3600);
        $this->assertFalse($this->dataStore->shouldUseForever());
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}