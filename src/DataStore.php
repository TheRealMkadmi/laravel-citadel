<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Drivers;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Laravel\Octane\Server;

class DataStore
{
    /**
     * The cache repository instance.
     *
     * @var \Illuminate\Contracts\Cache\Repository
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
     *
     * @return \Illuminate\Contracts\Cache\Repository
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
     *
     * @return \Illuminate\Contracts\Cache\Repository
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
     *
     * @return bool
     */
    protected function isRedisAvailable(): bool
    {
        return class_exists('Redis') && 
               config('database.redis.client', null) !== null &&
               !empty(config('database.redis.default', []));
    }

    /**
     * Get a value from the cache store.
     *
     * @param  string  $key
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
     * @param  string  $key
     * @param  mixed  $value
     * @param  int|\DateTimeInterface|\DateInterval|null  $ttl
     * @return void
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
     *
     * @param  string  $key
     * @return bool
     */
    public function removeValue(string $key): bool
    {
        return $this->cacheStore->forget($key);
    }

    /**
     * Increment a value in the cache store.
     *
     * @param  string  $key
     * @param  int  $amount
     * @return int|bool
     */
    public function increment(string $key, int $amount = 1)
    {
        return $this->cacheStore->increment($key, $amount);
    }

    /**
     * Check if a key exists in the cache store.
     *
     * @param  string  $key
     * @return bool
     */
    public function hasValue(string $key): bool
    {
        return $this->cacheStore->has($key);
    }

    /**
     * Get the cache store instance.
     *
     * @return \Illuminate\Contracts\Cache\Repository
     */
    public function getCacheStore(): Repository
    {
        return $this->cacheStore;
    }
}