<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use TheRealMkadmi\Citadel\Clients\IncolumitasApiClient;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class IpAnalyzer implements IRequestAnalyzer
{
    /**
     * The data store for caching results.
     *
     * @var \TheRealMkadmi\Citadel\DataStore\DataStore
     */
    protected DataStore $dataStore;

    /**
     * Cache TTL in seconds
     * 
     * @var int
     */
    protected int $cacheTtl;

    /**
     * Flag to enable or disable the analyzer
     * 
     * @var bool
     */
    protected bool $enabled;

    /**
     * The API client for IP intelligence
     * 
     * @var \TheRealMkadmi\Citadel\Clients\IncolumitasApiClient
     */
    protected IncolumitasApiClient $apiClient;

    /**
     * The weights for different IP characteristics
     * 
     * @var array
     */
    protected array $weights;

    /**
     * Constructor.
     * 
     * @param \TheRealMkadmi\Citadel\DataStore\DataStore $dataStore
     * @param \TheRealMkadmi\Citadel\Clients\IncolumitasApiClient $apiClient
     */
    public function __construct(DataStore $dataStore, IncolumitasApiClient $apiClient)
    {
        $this->dataStore = $dataStore;
        $this->apiClient = $apiClient;
        
        // Load all configuration values using Laravel's config helper
        $this->enabled = (bool) config('citadel.ip.enable_ip_analyzer', true);
        $this->cacheTtl = (int) config('citadel.cache.ip_analysis_ttl', 3600);
        
        // Load weights from configuration
        $this->weights = [
            'bogon' => (float) config('citadel.ip.weights.bogon', 80.0),
            'datacenter' => (float) config('citadel.ip.weights.datacenter', 30.0),
            'tor' => (float) config('citadel.ip.weights.tor', 60.0),
            'proxy' => (float) config('citadel.ip.weights.proxy', 50.0),
            'vpn' => (float) config('citadel.ip.weights.vpn', 40.0),
            'abuser' => (float) config('citadel.ip.weights.abuser', 70.0),
            'satellite' => (float) config('citadel.ip.weights.satellite', 10.0),
            'mobile' => (float) config('citadel.ip.weights.mobile', -10.0),
            'crawler' => (float) config('citadel.ip.weights.crawler', 20.0),
        ];
    }

    /**
     * Analyze the IP address making the request.
     *
     * @param Request $request
     * @return float
     */
    public function analyze(Request $request): float
    {
        if (!$this->enabled) {
            return 0.0;
        }

        $ip = $request->ip();
        
        // Try to get cached result
        $cacheKey = "ip_analyzer:{$ip}";
        $cachedScore = $this->dataStore->getValue($cacheKey);
        
        if ($cachedScore !== null) {
            return (float) $cachedScore;
        }
        
        // Calculate score based on IP intelligence
        $score = $this->calculateScore($ip);
        
        // Cache the score
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);
        
        return $score;
    }
    
    /**
     * Calculate the IP score based on IP intelligence.
     * 
     * @param string $ip
     * @return float
     */
    protected function calculateScore(string $ip): float
    {
        try {
            $result = $this->apiClient->query($ip);
            
            $score = 0.0;
            
            $fields = [
                'isBogon',
                'isDatacenter',
                'isTor',
                'isProxy',
                'isVpn',
                'isAbuser',
                'isSatellite',
                'isMobile',
                'isCrawler'
            ];

            foreach ($fields as $field) {
                if (property_exists($result, $field) && isset($this->weights[$field]) && !!$this->weights[$field]) {
                    $score += $this->weights[$field];
                }
            }
            
            return min(100.0, max(0.0, $score));
            
        } catch (\Exception $e) {
            report($e);
            return 0.0; // Return no risk on error
        }
    }
}