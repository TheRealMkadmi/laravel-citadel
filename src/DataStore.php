<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Drivers;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;
use Laravel\Octane\Server;

class DataStore
{
    /**
     * The cache repository instance.
     */
    protected Repository $cacheStore;

    /**
     * Create a new data store instance.
     */
    public function __construct()
    {
        $this->cacheStore = $this->resolveCacheStore();
    }

    /**
     * Resolve the appropriate cache store based on configuration and environment.
     */
    protected function resolveCacheStore(): Repository
    {
        $driver = config('citadel.cache.driver', 'auto');

        return match ($driver) {
            'auto' => $this->resolveAutoCacheStore(),
            default => Cache::store($driver),
        };
    }

    /**
     * Automatically determine the best cache store based on the environment.
     */
    protected function resolveAutoCacheStore(): Repository
    {
        // If Octane is available, use it as it's optimized for Octane environments
        if (app()->bound(Server::class) && config('citadel.cache.prefer_octane', true)) {
            return Cache::store('octane');
        }

        // If Redis is configured and available, use it for persistence
        if ($this->isRedisAvailable() && config('citadel.cache.prefer_redis', true)) {
            return Cache::store('redis');
        }

        // Fall back to the default cache store defined in cache.php
        return Cache::store(config('cache.default', 'array'));
    }

    /**
     * Check if Redis is available and configured.
     */
    protected function isRedisAvailable(): bool
    {
        return class_exists('Redis') &&
               config('database.redis.client', null) !== null &&
               ! empty(config('database.redis.default', []));
    }

    /**
     * Get a value from the cache store.
     *
     * @param  mixed  $default
     * @return mixed
     */
    public function getValue(string $key, $default = null)
    {
        return $this->cacheStore->get($key, $default);
    }

    /**
     * Store a value in the cache store.
     *
     * @param  mixed  $value
     * @param  int|\DateTimeInterface|\DateInterval|null  $ttl
     */
    public function setValue(string $key, $value, $ttl = null): void
    {
        if ($ttl === null && config('citadel.cache.use_forever', false)) {
            $this->cacheStore->forever($key, $value);
        } else {
            $ttl = $ttl ?? config('citadel.cache.default_ttl', 3600);
            $this->cacheStore->put($key, $value, $ttl);
        }
    }

    /**
     * Remove a value from the cache store.
     */
    public function removeValue(string $key): bool
    {
        return $this->cacheStore->forget($key);
    }

    /**
     * Increment a value in the cache store.
     *
     * @return int|bool
     */
    public function increment(string $key, int $amount = 1)
    {
        return $this->cacheStore->increment($key, $amount);
    }

    /**
     * Check if a key exists in the cache store.
     */
    public function hasValue(string $key): bool
    {
        return $this->cacheStore->has($key);
    }

    /**
     * Get the cache store instance.
     */
    public function getCacheStore(): Repository
    {
        return $this->cacheStore;
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
        // Only Redis supports sorted sets natively
        if ($this->isRedisAvailable()) {
            $result = Redis::zadd($key, $score, $member);

            // Set expiry if TTL is provided
            if ($ttl !== null) {
                Redis::expire($key, $ttl);
            }

            return $result;
        }

        // Fallback implementation for non-Redis stores
        // Use an array to simulate a sorted set
        $zset = $this->getValue($key, []);
        $zset[$member] = $score;

        // Sort the array by score
        asort($zset);

        $this->setValue($key, $zset, $ttl);

        return 1;
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
        if ($this->isRedisAvailable()) {
            return Redis::zremrangebyscore($key, $min, $max);
        }

        // Fallback implementation for non-Redis stores
        $zset = $this->getValue($key, []);
        $count = 0;

        foreach ($zset as $member => $score) {
            $checkMin = $min === '-inf' || $score >= (float) $min;
            $checkMax = $max === '+inf' || $score <= (float) $max;

            if ($checkMin && $checkMax) {
                unset($zset[$member]);
                $count++;
            }
        }

        $this->setValue($key, $zset);

        return $count;
    }

    /**
     * Get the number of members in a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     */
    public function zCard(string $key): int
    {
        if ($this->isRedisAvailable()) {
            return Redis::zcard($key);
        }

        // Fallback implementation for non-Redis stores
        $zset = $this->getValue($key, []);

        return count($zset);
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
        if ($this->isRedisAvailable()) {
            return Redis::zrange($key, $start, $stop, $withScores);
        }

        // Fallback implementation for non-Redis stores
        $zset = $this->getValue($key, []);
        $members = array_keys($zset);

        if (empty($members)) {
            return [];
        }

        // Handle negative indices (count from the end)
        if ($start < 0) {
            $start = count($members) + $start;
        }
        if ($stop < 0) {
            $stop = count($members) + $stop;
        }

        // Ensure indices are within bounds
        $start = max(0, $start);
        $stop = min(count($members) - 1, $stop);

        $result = [];
        if ($start <= $stop) {
            $slice = array_slice($members, $start, $stop - $start + 1);

            if ($withScores) {
                foreach ($slice as $member) {
                    $result[$member] = $zset[$member];
                }
            } else {
                $result = $slice;
            }
        }

        return $result;
    }

    /**
     * Execute multiple commands in a pipeline.
     *
     * @param  callable  $callback  The function that will receive the pipeline object
     * @return array The results of the commands
     */
    public function pipeline(callable $callback): array
    {
        if ($this->isRedisAvailable()) {
            return Redis::pipeline($callback);
        }

        // Create a simple pipeline simulator for non-Redis stores
        $pipeline = new class($this)
        {
            private $dataStore;

            private $commands = [];

            public function __construct($dataStore)
            {
                $this->dataStore = $dataStore;
            }

            public function zadd($key, $score, $member)
            {
                $this->commands[] = ['zadd', $key, $score, $member];

                return $this;
            }

            public function zremrangebyscore($key, $min, $max)
            {
                $this->commands[] = ['zremrangebyscore', $key, $min, $max];

                return $this;
            }

            public function expire($key, $ttl)
            {
                $this->commands[] = ['expire', $key, $ttl];

                return $this;
            }

            public function zcard($key)
            {
                $this->commands[] = ['zcard', $key];

                return $this;
            }

            public function zrange($key, $start, $stop, $withScores = false)
            {
                $this->commands[] = ['zrange', $key, $start, $stop, $withScores];

                return $this;
            }

            public function getCommands()
            {
                return $this->commands;
            }
        };

        $callback($pipeline);
        $commands = $pipeline->getCommands();
        $results = [];

        // Execute each command in sequence
        foreach ($commands as $command) {
            $method = $command[0];
            $args = array_slice($command, 1);

            switch ($method) {
                case 'zadd':
                    $results[] = $this->zAdd(...$args);
                    break;
                case 'zremrangebyscore':
                    $results[] = $this->zRemRangeByScore(...$args);
                    break;
                case 'expire':
                    // Handle expiry along with the value operations
                    $results[] = true;
                    break;
                case 'zcard':
                    $results[] = $this->zCard(...$args);
                    break;
                case 'zrange':
                    $results[] = $this->zRange(...$args);
                    break;
            }
        }

        return $results;
    }

    /**
     * Set the TTL on a key.
     *
     * @param  string  $key  The key to set the TTL on
     * @param  int  $ttl  The TTL in seconds
     */
    public function expire(string $key, int $ttl): bool
    {
        if ($this->isRedisAvailable()) {
            return Redis::expire($key, $ttl);
        }

        // For non-Redis stores, we use the TTL of the underlying cache system
        if ($this->hasValue($key)) {
            $value = $this->getValue($key);
            $this->setValue($key, $value, $ttl);

            return true;
        }

        return false;
    }
}
