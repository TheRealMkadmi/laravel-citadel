<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use TheRealMkadmi\Citadel\Clients\IncolumitasApiClient;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class IpAnalyzer extends AbstractAnalyzer
{
    /**
     * The API client for IP intelligence
     */
    protected IncolumitasApiClient $apiClient;

    /**
     * The weights for different IP characteristics
     */
    protected array $weights;

    /**
     * Indicates if this analyzer scans payload content.
     */
    protected bool $scansPayload = false;
    
    /**
     * Indicates if this analyzer makes external requests.
     */
    protected bool $active = true;

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore, IncolumitasApiClient $apiClient)
    {
        parent::__construct($dataStore);
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
     */
    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
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
                'isCrawler',
            ];

            foreach ($fields as $field) {
                if (property_exists($result, $field) && isset($this->weights[$field]) && (bool) $this->weights[$field]) {
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
