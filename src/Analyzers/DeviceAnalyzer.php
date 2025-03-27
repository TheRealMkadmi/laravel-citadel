<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class DeviceAnalyzer implements IRequestAnalyzer
{
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
     * Static cache for user agents to avoid repeated parsing
     *
     * @var array
     */
    protected static array $uaCache = [];

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->desktopScore = (float) config('citadel.device.desktop_score', 15.0);
        $this->botScore = (float) config('citadel.device.bot_score', 30.0);
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
        
        // Use cached result if we've seen this UA before
        if (isset(static::$uaCache[$userAgent])) {
            return static::$uaCache[$userAgent];
        }
        
        $score = 0.0;
        $deviceType = $this->detectDeviceType($userAgent);
        
        // Check for desktop devices
        if ($deviceType === 'desktop') {
            $score += $this->desktopScore;
        }
        
        // Check for known bot/tool user agents
        if ($this->isAutomatedTool($userAgent)) {
            $score += $this->botScore;
        }
        
        // Cache the result
        static::$uaCache[$userAgent] = $score;
        
        return $score;
    }
    
    /**
     * Detect the type of device based on User-Agent
     * 
     * @param string $userAgent
     * @return string 'mobile', 'desktop', or 'unknown'
     */
    protected function detectDeviceType(string $userAgent): string
    {
        // Common mobile device indicators in user agents
        $mobileKeywords = [
            'Android', 'webOS', 'iPhone', 'iPad', 'iPod', 'BlackBerry', 'IEMobile',
            'Opera Mini', 'Mobile', 'mobile', 'Windows Phone'
        ];
        
        // Check for mobile indicators
        foreach ($mobileKeywords as $keyword) {
            if (stripos($userAgent, $keyword) !== false) {
                return 'mobile';
            }
        }
        
        // Common desktop OS indicators
        $desktopKeywords = [
            'Windows NT', 'Macintosh', 'Mac OS X', 'Linux'
        ];
        
        // Check for desktop indicators
        foreach ($desktopKeywords as $keyword) {
            if (stripos($userAgent, $keyword) !== false && 
                !$this->containsAny($userAgent, ['Mobile', 'Android'])) {
                return 'desktop';
            }
        }
        
        // Default to unknown if we can't determine
        return 'unknown';
    }
    
    /**
     * Check if the user agent is likely an automated tool
     * 
     * @param string $userAgent
     * @return bool
     */
    protected function isAutomatedTool(string $userAgent): bool
    {
        $botPatterns = [
            'curl', 'wget', 'bot', 'crawl', 'spider', 'scrape',
            'HttpClient', 'Postman', 'Thunder Client', 'python-requests',
            'Lynx', 'Googlebot', 'YandexBot', 'BingBot'
        ];
        
        return $this->containsAny($userAgent, $botPatterns);
    }
    
    /**
     * Helper to check if a string contains any of the given patterns
     * 
     * @param string $haystack
     * @param array $needles
     * @return bool
     */
    protected function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (stripos($haystack, $needle) !== false) {
                return true;
            }
        }
        
        return false;
    }
}