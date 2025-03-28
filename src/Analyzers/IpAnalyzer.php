<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use TheRealMkadmi\Citadel\Clients\IncolumitasApiClient;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class IpAnalyzer extends AbstractAnalyzer
{
    /**
     * The API client for IP analysis.
     */
    protected IncolumitasApiClient $apiClient;

    /**
     * Weights for different IP characteristics.
     */
    protected array $weights;

    /**
     * Country-specific scoring settings.
     */
    protected array $countryScores;

    /**
     * Indicates if this analyzer scans payload content.
     */
    protected bool $scansPayload = false;

    /**
     * This analyzer makes external network requests.
     */
    protected bool $active = true;

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore, ?IncolumitasApiClient $apiClient = null)
    {
        parent::__construct($dataStore);

        // Load configuration settings
        $this->enabled = config('citadel.ip.enable_ip_analyzer', true);
        $this->cacheTtl = config(CitadelConfig::KEY_CACHE.'.ip_analysis_ttl', 7200);
        $this->weights = config(CitadelConfig::KEY_IP.'.weights', []);
        $this->countryScores = config(CitadelConfig::KEY_IP.'.country_scores', []);

        // Initialize API client
        $this->apiClient = $apiClient ?? new IncolumitasApiClient([
            'timeout' => 3,
            'retry' => true,
            'max_retries' => 1,
            'retry_delay' => 500,
        ]);
    }

    /**
     * Analyze the IP address of the request.
     */
    public function analyze(Request $request): float
    {
        if (!$this->enabled) {
            return 0.0;
        }

        // Get IP address from request
        $ip = $request->ip();
        if (!$ip) {
            return 0.0;
        }

        // Check cache first to reduce API calls
        $cacheKey = "ip_analysis:{$ip}";
        $cachedScore = $this->dataStore->getValue($cacheKey);
        if ($cachedScore !== null) {
            return (float) $cachedScore;
        }

        // Check if this is a private or reserved IP (not worth scoring)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return 0.0;
        }

        // Check IP characteristics through API
        $ipData = $this->apiClient->checkIp($ip);
        if (!$ipData) {
            // No data available, default to 0 score
            return 0.0;
        }

        // Calculate score based on IP characteristics
        $score = $this->calculateScore($ipData, $ip);

        // Cache the result
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);

        return $score;
    }

    /**
     * Calculate score based on IP characteristics.
     */
    protected function calculateScore(array $ipData, string $ip): float
    {
        $score = 0.0;

        // Score based on IP characteristics (datacenter, VPN, etc.)
        foreach ($this->weights as $characteristic => $weight) {
            if (isset($ipData[$characteristic]) && $ipData[$characteristic] === true) {
                $score += (float) $weight;
            }
        }

        // Score based on country
        if (isset($ipData['country'])) {
            $country = $ipData['country'];

            // Check if country is in high-risk list
            $highRiskCountries = $this->countryScores['high_risk_countries'] ?? [];
            if (!empty($highRiskCountries) && in_array($country, $highRiskCountries)) {
                $score += (float) ($this->countryScores['high_risk_score'] ?? 30.0);
            }

            // Check if country is in trusted list (can reduce score)
            $trustedCountries = $this->countryScores['trusted_countries'] ?? [];
            if (!empty($trustedCountries) && in_array($country, $trustedCountries)) {
                $score += (float) ($this->countryScores['trusted_score'] ?? -15.0);
            }
        }

        // Ensure score is never negative
        return max(0.0, $score);
    }
}
