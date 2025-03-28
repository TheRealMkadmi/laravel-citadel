<?php

namespace TheRealMkadmi\Citadel\DataStore;

interface DataStore
{
    /**
     * Get a value from the data store.
     *
     * @param  string  $key  The cache key
     * @return mixed The stored value or null if not found
     */
    public function getValue(string $key): mixed;

    /**
     * Store a value in the data store.
     *
     * @param  string  $key  The cache key
     * @param  mixed  $value  The value to store
     * @param  int|null  $ttl  Time-to-live in seconds, null for default
     * @return bool Success indicator
     */
    public function setValue(string $key, mixed $value, ?int $ttl = null): bool;

    /**
     * Remove a value from the data store.
     *
     * @param  string  $key  The cache key
     * @return bool Success indicator
     */
    public function removeValue(string $key): bool;

    /**
     * Add a member with score to a sorted set.
     *
     * @param  string  $key  The sorted set key
     * @param  float|int  $score  The score
     * @param  mixed  $member  The member to add
     * @param  int|null  $ttl  Optional TTL in seconds
     * @return bool|int Number of elements added or false on failure
     */
    public function zAdd(string $key, float|int $score, mixed $member, ?int $ttl = null): bool|int;

    /**
     * Execute multiple commands in a pipeline.
     *
     * @param  callable  $callback  Function to define pipeline operations
     * @return array Results of pipeline execution
     */
    public function pipeline(callable $callback): array;
}
