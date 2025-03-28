<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\DataStore;

use Illuminate\Contracts\Cache\Repository;

abstract class AbstractDataStore implements DataStore
{
    /**
     * The cache repository instance.
     */
    protected Repository $cacheStore;

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
}
