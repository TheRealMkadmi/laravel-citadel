<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\DataStore;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;

class RedisDataStore extends AbstractDataStore
{
    /**
     * Redis store identifier constant
     */
    public const STORE_IDENTIFIER = 'redis';

    /**
     * Create a new Redis data store instance.
     */
    public function __construct()
    {
        $this->cacheStore = Cache::store(self::STORE_IDENTIFIER);
    }

    /**
     * Get a value from the cache store with proper key prefixing.
     *
     * @param  string  $key  The cache key
     * @param  mixed  $default  Default value if key doesn't exist
     * @return mixed The stored value or default if not found
     */
    public function getValue(string $key, mixed $default = null): mixed
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return $this->cacheStore->get($prefixedKey, $default);
    }

    /**
     * Store a value in the cache store with proper key prefixing.
     *
     * @param  string  $key  The cache key
     * @param  mixed  $value  The value to store
     * @param  int|null  $ttl  Time-to-live in seconds, null for default
     * @return bool Success indicator
     */
    public function setValue(string $key, mixed $value, ?int $ttl = null): bool
    {
        $prefixedKey = $this->getPrefixedKey($key);
        $ttl = $ttl ?? $this->getDefaultTtl();

        if ($this->shouldUseForever()) {
            $this->cacheStore->forever($prefixedKey, $value);
        } else {
            $this->cacheStore->put($prefixedKey, $value, $ttl);
        }

        return true;
    }

    /**
     * Remove a value from the cache store.
     *
     * @param  string  $key  The key to remove
     * @return bool Success indicator
     */
    public function removeValue(string $key): bool
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return $this->cacheStore->forget($prefixedKey);
    }

    /**
     * Add a member with score to a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     * @param  float|int  $score  The score for the member
     * @param  mixed  $member  The member to add
     * @param  int|null  $ttl  Optional TTL in seconds
     * @return bool|int Number of elements added or false on failure
     */
    public function zAdd(string $key, float|int $score, mixed $member, ?int $ttl = null): bool|int
    {
        $prefixedKey = $this->getPrefixedKey($key);
        $result = Redis::zadd($prefixedKey, $score, $member);

        if ($ttl !== null || ! $this->shouldUseForever()) {
            $ttl = $ttl ?? $this->getDefaultTtl();
            Redis::expire($prefixedKey, $ttl);
        }

        return $result;
    }

    /**
     * Remove members with scores in the given range from a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     * @param  float|int|string  $min  The minimum score (or '-inf')
     * @param  float|int|string  $max  The maximum score (or '+inf')
     * @return int The number of members removed
     */
    public function zRemRangeByScore(string $key, float|int|string $min, float|int|string $max): int
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return Redis::zremrangebyscore($prefixedKey, $min, $max);
    }

    /**
     * Get the number of members in a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     * @return int The number of members
     */
    public function zCard(string $key): int
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return Redis::zcard($prefixedKey);
    }

    /**
     * Get a range of members from a sorted set by index.
     *
     * @param  string  $key  The key of the sorted set
     * @param  int  $start  The start index
     * @param  int  $stop  The stop index
     * @param  bool  $withScores  Whether to return scores along with members
     * @return array The range of members
     */
    public function zRange(string $key, int $start, int $stop, bool $withScores = false): array
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return Redis::zrange($prefixedKey, $start, $stop, $withScores);
    }

    /**
     * Remove a range of members from sorted set by rank (position).
     *
     * @param  string  $key  The sorted set key
     * @param  int  $start  Start position
     * @param  int  $stop  Stop position (inclusive)
     * @return int Number of elements removed
     */
    public function zRemRangeByRank(string $key, int $start, int $stop): int
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return Redis::zremrangebyrank($prefixedKey, $start, $stop);
    }

    /**
     * Execute multiple commands in a pipeline.
     *
     * @param  callable  $callback  The function that will receive the pipeline object
     * @return array The results of the commands
     */
    public function pipeline(callable $callback): array
    {
        return Redis::pipeline($callback);
    }

    /**
     * Set the TTL on a key.
     *
     * @param  string  $key  The key to set the TTL on
     * @param  int  $ttl  The TTL in seconds
     * @return bool Success indicator
     */
    public function expire(string $key, int $ttl): bool
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return Redis::expire($prefixedKey, $ttl);
    }

    /**
     * Check if a key exists in the data store.
     *
     * @param  string  $key  The key to check
     * @return bool Whether the key exists
     */
    public function hasValue(string $key): bool
    {
        $prefixedKey = $this->getPrefixedKey($key);

        return $this->cacheStore->has($prefixedKey);
    }
}
