<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\DataStores;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;

class RedisDataStore extends AbstractDataStore
{
    /**
     * Create a new Redis data store instance.
     */
    public function __construct()
    {
        $this->cacheStore = Cache::store('redis');
    }

    /**
     * Get a value from the cache store with proper key prefixing.
     *
     * @param  mixed  $default
     * @return mixed
     */
    public function getValue(string $key, $default = null)
    {
        $prefixedKey = config('citadel.cache.key_prefix').$key;

        return $this->cacheStore->get($prefixedKey, $default);
    }

    /**
     * Store a value in the cache store with proper key prefixing.
     *
     * @param  mixed  $value
     * @param  int|\DateTimeInterface|\DateInterval|null  $ttl
     */
    public function setValue(string $key, $value, $ttl = null): void
    {
        $prefixedKey = config('citadel.cache.key_prefix').$key;
        $ttl = $ttl ?? config('citadel.cache.default_ttl', 3600);

        if (config('citadel.cache.use_forever', false)) {
            $this->cacheStore->forever($prefixedKey, $value);
        } else {
            $this->cacheStore->put($prefixedKey, $value, $ttl);
        }
    }

    /**
     * Add a member with score to a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     * @param  float|int  $score  The score for the member
     * @param  mixed  $member  The member to add
     * @param  int|null  $ttl  Optional TTL in seconds
     * @return bool|int
     */
    public function zAdd(string $key, float|int $score, mixed $member, ?int $ttl = null)
    {
        $prefixedKey = config('citadel.cache.key_prefix').$key;
        $result = Redis::zadd($prefixedKey, $score, $member);

        if ($ttl !== null || ! config('citadel.cache.use_forever', false)) {
            $ttl = $ttl ?? config('citadel.cache.default_ttl', 3600);
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
        return Redis::zremrangebyscore($key, $min, $max);
    }

    /**
     * Get the number of members in a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     */
    public function zCard(string $key): int
    {
        return Redis::zcard($key);
    }

    /**
     * Get a range of members from a sorted set by index.
     *
     * @param  string  $key  The key of the sorted set
     * @param  int  $start  The start index
     * @param  int  $stop  The stop index
     * @param  bool  $withScores  Whether to return scores along with members
     */
    public function zRange(string $key, int $start, int $stop, bool $withScores = false): array
    {
        return Redis::zrange($key, $start, $stop, $withScores);
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
     */
    public function expire(string $key, int $ttl): bool
    {
        return Redis::expire($key, $ttl);
    }
}
