<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Reefki\DeviceDetector\DeviceDetector;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\AnalyzerType;

class DeviceAnalyzer extends AbstractAnalyzer
{
    /**
     * Config key prefix for device analyzer
     */
    private const CONFIG_PREFIX = 'citadel.device';

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
     * Bot detection patterns
     */
    protected array $botPatterns = [];

    /**
     * Whether this takes active action against the request or the client to decide
     */
    protected AnalyzerType $analyzerType = AnalyzerType::PASSIVE;

    /**
     * Local device detection instance
     */
    protected ?DeviceDetector $deviceDetector = null;

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);

        // Load all configuration values at once
        $this->loadConfigurationValues();
    }

    /**
     * Load configuration values once during initialization
     */
    protected function loadConfigurationValues(): void
    {
        // Load analyzer state and scores
        $this->enabled = config(self::CONFIG_PREFIX.'.enable_device_analyzer', true);
        $this->smartphoneScore = (float) config(CitadelConfig::KEY_DEVICE.'.smartphone_score', 0.0);
        $this->tabletScore = (float) config(CitadelConfig::KEY_DEVICE.'.tablet_score', 0.0);
        $this->desktopScore = (float) config(CitadelConfig::KEY_DEVICE.'.desktop_score', 10.0);
        $this->botScore = (float) config(CitadelConfig::KEY_DEVICE.'.bot_score', 100.0);
        $this->unknownScore = (float) config(CitadelConfig::KEY_DEVICE.'.unknown_score', 20.0);
        $this->cacheTtl = (int) config(CitadelConfig::KEY_CACHE.'.device_detection_ttl', 86400);

        // Load bot patterns from config or use defaults
        $this->botPatterns = config(self::CONFIG_PREFIX.'.bot_patterns', [
            'bot', 'crawl', 'spider', 'slurp', 'search', 'fetch', 'monitor',
            'scrape', 'extract', 'scan', 'wget', 'curl', 'http', 'python',
            'java/', 'libwww', 'perl', 'phantomjs', 'headless', 'automation',
            'lighthouse', 'pagespeed', 'pingdom', 'gtmetrix',
        ]);
    }

    /**
     * Analyze the device making the request.
     */
    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            return 0.0;
        }

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

        // Cache the result with appropriate TTL
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);

        return $score;
    }

    /**
     * Detect the type of device from user agent string.
     */
    protected function detectDeviceType(string $userAgent): float
    {
        // Check for bot patterns first (fast check before more intensive device detection)
        if ($this->isBot($userAgent)) {
            return $this->botScore;
        }

        try {
            // Use lazy-loaded device detector instance
            $detector = $this->getDeviceDetector();
            $result = $detector->detectRequest(request());

            // Detect device type using a more efficient approach
            if ($result->isSmartphone()) {
                return $this->smartphoneScore;
            }

            if ($result->isTablet()) {
                return $this->tabletScore;
            }

            if ($result->isDesktop()) {
                return $this->desktopScore;
            }
        } catch (\Throwable $e) {
            // Use report() for Laravel-friendly exception handling
            report($e);
        }

        // Unknown device type
        return $this->unknownScore;
    }

    /**
     * Get the device detector instance (lazy loading)
     */
    protected function getDeviceDetector(): DeviceDetector
    {
        if ($this->deviceDetector === null) {
            $this->deviceDetector = app(DeviceDetector::class);
        }

        return $this->deviceDetector;
    }

    /**
     * Check if user agent string looks like a bot.
     */
    protected function isBot(string $userAgent): bool
    {
        // Quick check for empty user agent (often bots)
        if (empty($userAgent)) {
            return true;
        }

        // Convert to lowercase once for all pattern checks
        $userAgentLower = Str::lower($userAgent);

        // Check if user agent contains any bot patterns (case insensitive)
        foreach ($this->botPatterns as $pattern) {
            if (Str::contains($userAgentLower, $pattern)) {
                return true;
            }
        }

        // Check for other bot indicators
        if (Str::startsWith($userAgentLower, 'mozilla/5.0') && Str::length($userAgent) < 40) {
            // Suspiciously short Mozilla UA string (often bots)
            return true;
        }

        return false;
    }
}
