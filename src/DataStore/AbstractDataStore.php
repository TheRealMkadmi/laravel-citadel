<?php

namespace TheRealMkadmi\Citadel\DataStore;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Config;
use TheRealMkadmi\Citadel\Config\CitadelConfig;

abstract class AbstractDataStore implements DataStore
{
    /**
     * The cache repository instance.
     *
     * @var Repository
     */
    protected Repository $cacheStore;
    
    /**
     * Get a value from the data store.
     * 
     * @param string $key The cache key
     * @return mixed The stored value or null if not found
     */
    abstract public function getValue(string $key): mixed;

    /**
     * Store a value in the data store.
     * 
     * @param string $key The cache key
     * @param mixed $value The value to store
     * @param int|null $ttl Time-to-live in seconds, null for default
     * @return bool Success indicator
     */
    abstract public function setValue(string $key, mixed $value, ?int $ttl = null): bool;

    /**
     * Remove a value from the data store.
     * 
     * @param string $key The cache key
     * @return bool Success indicator
     */
    abstract public function removeValue(string $key): bool;

    /**
     * Add a member with score to a sorted set.
     * 
     * @param string $key The sorted set key
     * @param float|int $score The score
     * @param mixed $member The member to add
     * @param int|null $ttl Optional TTL in seconds
     * @return bool|int Number of elements added or false on failure
     */
    abstract public function zAdd(string $key, float|int $score, mixed $member, ?int $ttl = null): bool|int;

    /**
     * Execute multiple commands in a pipeline.
     * 
     * @param callable $callback Function to define pipeline operations
     * @return array Results of pipeline execution
     */
    abstract public function pipeline(callable $callback): array;

    /**
     * Get the configured key prefix.
     *
     * @return string The configured key prefix
     */
    protected function getPrefix(): string
    {
        return Config::get(CitadelConfig::KEY_CACHE_PREFIX, 'citadel:');
    }

    /**
     * Get the prefixed key for storage.
     * 
     * @param string $key The original key
     * @return string The prefixed key
     */
    protected function getPrefixedKey(string $key): string
    {
        return $this->getPrefix() . $key;
    }
    
    /**
     * Get the default TTL from configuration.
     * 
     * @return int Default TTL in seconds
     */
    protected function getDefaultTtl(): int
    {
        return Config::get(CitadelConfig::KEY_CACHE_DEFAULT_TTL, 3600);
    }
    
    /**
     * Check if cache should use "forever" storage.
     * 
     * @return bool Whether to use forever storage
     */
    protected function shouldUseForever(): bool
    {
        // Use forever storage if explicitly configured or if TTL is 0 or negative
        $useForever = Config::get(CitadelConfig::KEY_CACHE_USE_FOREVER, false);
        $ttl = $this->getDefaultTtl();
        
        return $useForever || $ttl <= 0;
    }
    
    /**
     * Calculate TTL in seconds from milliseconds, applying buffer multiplier.
     *
     * @param int $milliseconds Window size in milliseconds
     * @return int TTL in seconds with buffer applied
     */
    protected function calculateTtl(int $milliseconds): int
    {
        $seconds = $milliseconds / 1000;
        $multiplier = Config::get('citadel.burstiness.ttl_buffer_multiplier', 2);
        
        return $seconds * $multiplier;
    }
}
