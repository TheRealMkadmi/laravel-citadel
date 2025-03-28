<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Reefki\DeviceDetector\Device;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class DeviceAnalyzer extends AbstractAnalyzer
{
    /**
     * The score to add for smartphone devices
     */
    protected float $smartphoneScore;

    /**
     * The score to add for tablet devices
     */
    protected float $tabletScore;

    /**
     * The score to add for desktop devices
     */
    protected float $desktopScore;

    /**
     * The score to add for bot/automated tools
     */
    protected float $botScore;

    /**
     * The score to add for unknown devices
     */
    protected float $unknownScore;

    /**
     * Indicates if this analyzer scans payload content.
     */
    protected bool $scansPayload = false;

    /**
     * This analyzer doesn't make external network requests.
     */
    protected bool $active = false;

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);

        // Load all configuration values using Laravel's config helper with our config constants
        $this->enabled = config('citadel.device.enable_device_analyzer', true);
        $this->smartphoneScore = (float) config(CitadelConfig::KEY_DEVICE.'.smartphone_score', 0.0);
        $this->tabletScore = (float) config(CitadelConfig::KEY_DEVICE.'.tablet_score', 0.0);
        $this->desktopScore = (float) config(CitadelConfig::KEY_DEVICE.'.desktop_score', 10.0);
        $this->botScore = (float) config(CitadelConfig::KEY_DEVICE.'.bot_score', 100.0);
        $this->unknownScore = (float) config(CitadelConfig::KEY_DEVICE.'.unknown_score', 20.0);
        $this->cacheTtl = (int) config(CitadelConfig::KEY_CACHE.'.device_detection_ttl', 86400);
    }

    /**
     * Analyze the device making the request.
     */
    public function analyze(Request $request): float
    {
        $userAgent = $request->userAgent() ?? '';
        
        // If user agent is empty, return unknown score
        if (empty($userAgent)) {
            return $this->unknownScore;
        }
        
        // Create cache key based on user agent hash
        $cacheKey = 'device:'.md5($userAgent);
        
        // Check if we have a cached result
        $cachedResult = $this->dataStore->getValue($cacheKey);
        if ($cachedResult !== null) {
            return (float) $cachedResult;
        }
        
        // Detect device type
        $score = $this->detectDeviceType($userAgent);
        
        // Cache the result
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);
        
        return $score;
    }
    
    /**
     * Detect the type of device from user agent string.
     */
    protected function detectDeviceType(string $userAgent): float
    {
        // Check for bot patterns first
        if ($this->isBot($userAgent)) {
            return $this->botScore;
        }
        
        try {
            // Use Reefki's device detector with lazy loading
            $device = app(Device::class);
            $device->setUserAgent($userAgent);
            
            // Detect device type
            if ($device->isSmartphone()) {
                return $this->smartphoneScore;
            } elseif ($device->isTablet()) {
                return $this->tabletScore;
            } elseif ($device->isDesktop()) {
                return $this->desktopScore;
            }
        } catch (\Exception $e) {
            // Log exception but continue with detection
            // Device detection shouldn't break the application
            report($e);
        }
        
        // Unknown device type
        return $this->unknownScore;
    }
    
    /**
     * Check if user agent string looks like a bot.
     */
    protected function isBot(string $userAgent): bool
    {
        // Common bot keywords
        $botPatterns = [
            'bot', 'crawl', 'spider', 'slurp', 'search', 'fetch', 'monitor',
            'scrape', 'extract', 'scan', 'wget', 'curl', 'http', 'python', 
            'java/', 'libwww', 'perl', 'phantomjs', 'headless', 'automation',
        ];
        
        // Check if user agent contains any bot patterns (case insensitive)
        $userAgentLower = Str::lower($userAgent);
        
        foreach ($botPatterns as $pattern) {
            if (Str::contains($userAgentLower, $pattern)) {
                return true;
            }
        }
        
        return false;
    }
}
