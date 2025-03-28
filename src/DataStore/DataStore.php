<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\DataStore;

interface DataStore
{
    /**
     * Get a value from the cache store.
     *
     * @param  mixed  $default
     * @return mixed
     */
    public function getValue(string $key, $default = null);

    /**
     * Store a value in the cache store.
     *
     * @param  mixed  $value
     * @param  int|\DateTimeInterface|\DateInterval|null  $ttl
     */
    public function setValue(string $key, $value, $ttl = null): void;

    /**
     * Remove a value from the cache store.
     */
    public function removeValue(string $key): bool;

    /**
     * Increment a value in the cache store.
     *
     * @return int|bool
     */
    public function increment(string $key, int $amount = 1);

    /**
     * Check if a key exists in the cache store.
     */
    public function hasValue(string $key): bool;

    /**
     * Add a member with score to a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     * @param  float|int  $score  The score for the member
     * @param  mixed  $member  The member to add
     * @param  int|null  $ttl  Optional TTL in seconds
     * @return bool|int
     */
    public function zAdd(string $key, float|int $score, mixed $member, ?int $ttl = null);

    /**
     * Remove members with scores in the given range from a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     * @param  float|int|string  $min  The minimum score (or '-inf')
     * @param  float|int|string  $max  The maximum score (or '+inf')
     * @return int The number of members removed
     */
    public function zRemRangeByScore(string $key, float|int|string $min, float|int|string $max): int;

    /**
     * Get the number of members in a sorted set.
     *
     * @param  string  $key  The key of the sorted set
     */
    public function zCard(string $key): int;

    /**
     * Get a range of members from a sorted set by index.
     *
     * @param  string  $key  The key of the sorted set
     * @param  int  $start  The start index
     * @param  int  $stop  The stop index
     * @param  bool  $withScores  Whether to return scores along with members
     */
    public function zRange(string $key, int $start, int $stop, bool $withScores = false): array;

    /**
     * Execute multiple commands in a pipeline.
     *
     * @param  callable  $callback  The function that will receive the pipeline object
     * @return array The results of the commands
     */
    public function pipeline(callable $callback): array;

    /**
     * Set the TTL on a key.
     *
     * @param  string  $key  The key to set the TTL on
     * @param  int  $ttl  The TTL in seconds
     */
    public function expire(string $key, int $ttl): bool;
}
