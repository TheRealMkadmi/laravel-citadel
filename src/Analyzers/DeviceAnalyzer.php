<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Reefki\DeviceDetector\Device;
use TheRealMkadmi\Citadel\Contracts\DataStore;

class DeviceAnalyzer implements IRequestAnalyzer
{
    /**
     * The data store for caching results.
     *
     * @var \TheRealMkadmi\Citadel\Contracts\DataStore
     */
    protected DataStore $dataStore;

    /**
     * The score to add for smartphone devices
     *
     * @var float
     */
    protected float $smartphoneScore;

    /**
     * The score to add for tablet devices
     *
     * @var float
     */
    protected float $tabletScore;

    /**
     * The score to add for desktop devices
     *
     * @var float
     */
    protected float $desktopScore;

    /**
     * The score to add for bot/automated tools
     *
     * @var float
     */
    protected float $botScore;

    /**
     * The score to add for unknown devices
     *
     * @var float
     */
    protected float $unknownScore;

    /**
     * Cache TTL in seconds
     * 
     * @var int
     */
    protected int $cacheTtl;

    /**
     * Constructor.
     * 
     * @param \TheRealMkadmi\Citadel\Contracts\DataStore $dataStore
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
        
        // Load all configuration values using Laravel's config helper
        $this->smartphoneScore = (float) config('citadel.device.smartphone_score', 0.0);
        $this->tabletScore = (float) config('citadel.device.tablet_score', 0.0);
        $this->desktopScore = (float) config('citadel.device.desktop_score', 10.0);
        $this->botScore = (float) config('citadel.device.bot_score', 100.0);
        $this->unknownScore = (float) config('citadel.device.unknown_score', 20.0);
        $this->cacheTtl = (int) config('citadel.cache.device_detection_ttl', 86400);
    }

    /**
     * Analyze the device making the request.
     *
     * @param Request $request
     * @return float
     */
    public function analyze(Request $request): float
    {
        $userAgent = $request->userAgent() ?? '';
        
        // Create a cache key with proper prefix
        $cacheKey = Str::start(
            'device:' . md5($userAgent), 
            config('citadel.cache.key_prefix', 'citadel:')
        );
        
        // Try to get cached result first
        $cachedScore = $this->dataStore->getValue($cacheKey);
        if ($cachedScore !== null) {
            return (float) $cachedScore;
        }
        
        // Calculate the score if not in cache
        $score = $this->calculateScore($userAgent, $request);
        
        // Cache the result using configured TTL
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);
        
        return $score;
    }
    
    /**
     * Calculate the device score based on user agent.
     * 
     * @param string $userAgent
     * @param Request $request
     * @return float
     */
    protected function calculateScore(string $userAgent, Request $request): float
    {
        $score = 0.0;
        
        $device = Device::detect($userAgent, $request->server());
        
        // Use match expression for more idiomatic Laravel code
        $score += match (true) {
            $device->isSmartphone() => $this->smartphoneScore,
            $device->isTablet() => $this->tabletScore,
            $device->isDesktop() => $this->desktopScore,
            $device->isBot() => $this->botScore,
            default => $this->unknownScore,
        };

        return $score;
    }
}