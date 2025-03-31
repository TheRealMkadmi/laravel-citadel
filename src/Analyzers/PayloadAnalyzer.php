<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class PayloadAnalyzer extends AbstractAnalyzer
{
    /**
     * Known suspicious patterns in request payloads
     */
    protected array $suspiciousPatterns;

    /**
     * Maximum analysis score
     */
    protected float $maxScore;

    /**
     * Score threshold for potential threats
     */
    protected float $threatThreshold;

    /**
     * Cached entropy calculations
     */
    protected array $entropyCache = [];

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);

        // Load all configuration values using Laravel's config helper
        $this->enabled = config('citadel.payload.enable_payload_analyzer', true);
        $this->cacheTtl = config('citadel.payload.cache_ttl', config('citadel.cache.payload_analysis_ttl', 3600));
        $this->maxScore = config('citadel.payload.max_score', 100.0);
        $this->threatThreshold = config('citadel.payload.threat_threshold', 40.0);

        // Load suspicious patterns from config - only once during initialization
        $this->suspiciousPatterns = config('citadel.payload.suspicious_patterns') ?? $this->getDefaultPatterns();
    }

    /**
     * Analyze the request payload.
     */
    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            return 0.0;
        }

        // Use the getFingerprint request macro to get the fingerprint
        $fingerprint = $request->getFingerprint();
        $cacheKey = "payload_analysis:{$fingerprint}";

        // Check if we have a cached result
        $cached = $this->dataStore->getValue($cacheKey);
        if ($cached !== null) {
            return (float) $cached;
        }

        // Extract and normalize all request data for comprehensive analysis
        $analysisData = $this->extractRequestData($request);

        // Calculate score using advanced pattern detection
        $analysisResult = $this->performAdvancedAnalysis($analysisData, $request);

        // Cache the result
        $this->dataStore->setValue($cacheKey, $analysisResult['score'], $this->cacheTtl);

        // Log high-risk detections for security monitoring
        if ($analysisResult['score'] >= $this->threatThreshold) {
            $this->logSecurityThreat($request, $analysisResult);
        }

        return $analysisResult['score'];
    }

    /**
     * This analyzer requires a request body to function
     */
    public function requiresRequestBody(): bool
    {
        return true;
    }

    /**
     * This analyzer doesn't use external resources
     */
    public function usesExternalResources(): bool
    {
        return false;
    }

    // Other methods remain unchanged...
}
