<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\DataStore;

use Illuminate\Support\Facades\Cache;
use TheRealMkadmi\Citadel\Config\CitadelConfig;

class ArrayDataStore extends AbstractDataStore
{
    /**
     * Array store identifier constant
     */
    public const STORE_IDENTIFIER = 'array';
    
    /**
     * Create a new Array data store instance.
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
     * @param  mixed  $value
     * @param  int|\DateTimeInterface|\DateInterval|null  $ttl
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
     * Add a member with score to a sorted set.
     *
     * @param  string  $key  The sorted set key
     * @param  float|int  $score  The score
     * @param  mixed  $member  The member to add
     * @param  int|null  $ttl  Optional TTL in seconds
     * @return bool|int  Number of elements added or false on failure
     */
    public function zAdd(string $key, float|int $score, mixed $member, ?int $ttl = null): bool|int
    {
        // Get or create the sorted set
        $zset = $this->getValue($key, []);
        $zset[$member] = $score;

        // Sort the array by score
        asort($zset);

        // Store with configured TTL
        $this->setValue($key, $zset, $ttl);

        return 1; // Added/updated one member
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

        if ($count > 0) {
            $this->setValue($key, $zset);
        }

        return $count;
    }

    /**
     * Get the number of members in a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     */
    public function zCard(string $key): int
    {
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
        $zset = $this->getValue($key, []);

        // Sort by score (value)
        asort($zset);
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
        // Create a simple pipeline simulator
        $pipeline = new class($this) {
            private ArrayDataStore $dataStore;
            private array $commands = [];

            public function __construct(ArrayDataStore $dataStore)
            {
                $this->dataStore = $dataStore;
            }

            public function zadd(string $key, float|int $score, mixed $member): self
            {
                $this->commands[] = ['zadd', $key, $score, $member];
                return $this;
            }

            public function zremrangebyscore(string $key, float|int|string $min, float|int|string $max): self
            {
                $this->commands[] = ['zremrangebyscore', $key, $min, $max];
                return $this;
            }

            public function expire(string $key, int $ttl): self
            {
                $this->commands[] = ['expire', $key, $ttl];
                return $this;
            }

            public function zcard(string $key): self
            {
                $this->commands[] = ['zcard', $key];
                return $this;
            }

            public function zrange(string $key, int $start, int $stop, bool $withScores = false): self
            {
                $this->commands[] = ['zrange', $key, $start, $stop, $withScores];
                return $this;
            }

            public function getCommands(): array
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
                    // Handle expiry along with value operations in zAdd
                    $results[] = $this->expire(...$args);
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
        // For the Array store, we use the TTL of the underlying cache system
        if ($this->hasValue($key)) {
            $value = $this->getValue($key);
            $this->setValue($key, $value, $ttl);

            return true;
        }

        return false;
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

    /**
     * Remove a value from the data store.
     *
     * @param  string  $key  The key to remove
     * @return bool Success indicator
     */
    public function removeValue(string $key): bool
    {
        $prefixedKey = $this->getPrefixedKey($key);
        return $this->cacheStore->forget($prefixedKey);
    }
}
