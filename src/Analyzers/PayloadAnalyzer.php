<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Contracts\DataStore;

class PayloadAnalyzer implements IRequestAnalyzer
{
    /**
     * The data store for caching results.
     *
     * @var \TheRealMkadmi\Citadel\Contracts\DataStore
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
     * Known suspicious patterns in request payloads
     * 
     * @var array
     */
    protected array $suspiciousPatterns;

    /**
     * Constructor.
     * 
     * @param \TheRealMkadmi\Citadel\Contracts\DataStore $dataStore
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
        
        // Load all configuration values using Laravel's config helper
        $this->enabled = (bool) config('citadel.payload.enable_payload_analyzer', true);
        $this->cacheTtl = (int) config('citadel.cache.payload_analysis_ttl', 3600);
        
        // Load suspicious patterns from config
        $this->suspiciousPatterns = config('citadel.payload.suspicious_patterns', [
            'sql_injection' => [
                'pattern' => '/\b(union|select|insert|update|delete|drop|alter|truncate|exec|declare|sleep|benchmark)\b/i',
                'score' => 50.0,
            ],
            'xss' => [
                'pattern' => '/<\s*script|<\s*iframe|javascript\s*:|alert\s*\(|onerror\s*=|onload\s*=/i',
                'score' => 40.0,
            ],
            'command_injection' => [
                'pattern' => '/;\s*(bash|sh|cmd|powershell)|&&|\|\|/i',
                'score' => 60.0,
            ],
            'path_traversal' => [
                'pattern' => '/\.\.(\\/|\\\\)|\/etc\/passwd/i',
                'score' => 45.0,
            ],
        ]);
    }

    /**
     * Analyze the request payload.
     *
     * @param Request $request
     * @return float
     */
    public function analyze(Request $request): float
    {
        if (!$this->enabled) {
            return 0.0;
        }

        // Get cache key based on request fingerprint or IP if no fingerprint
        $fingerprint = $request->header('X-Fingerprint') ?? md5($request->ip() . $request->userAgent());
        $cacheKey = "payload_analysis:{$fingerprint}";
        
        // Check if we have a cached result
        $cached = $this->dataStore->getValue($cacheKey);
        if ($cached !== null) {
            return (float) $cached;
        }
        
        // Get the request body fields, whether it's JSON or form data
        $requestBody = $request->all();
        $requestJson = $request->isJson() ? json_encode($requestBody) : '';
        
        // Also check raw query string and headers for suspicious patterns
        $queryString = $request->getQueryString() ?? '';
        $headers = json_encode($request->headers->all());
        
        // Combine all input sources for analysis
        $allInput = $requestJson . ' ' . $queryString . ' ' . $headers;
        
        // Calculate score
        $score = $this->calculateScore($allInput, $request);
        
        // Cache the result
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);
        
        return $score;
    }
    
    /**
     * Calculate the score based on request payload.
     * 
     * @param string $payload Combined request payload
     * @param Request $request
     * @return float
     */
    protected function calculateScore(string $payload, Request $request): float
    {
        $score = 0.0;
        $matches = [];
        
        // Check for suspicious patterns
        foreach ($this->suspiciousPatterns as $name => $pattern) {
            if (preg_match($pattern['pattern'], $payload)) {
                $score += $pattern['score'];
                $matches[] = $name;
            }
        }
        
        // Check request size - larger payloads can be suspicious
        $contentLength = (int) $request->headers->get('Content-Length', 0);
        $maxSize = config('citadel.payload.max_size', 1048576); // Default 1MB
        
        if ($contentLength > $maxSize) {
            $sizeScore = config('citadel.payload.large_payload_score', 20.0);
            $score += $sizeScore;
            $matches[] = 'large_payload';
        }
        
        // Check for very large number of parameters which can indicate automation
        $paramCount = count($request->all());
        $maxParams = config('citadel.payload.max_params', 100);
        
        if ($paramCount > $maxParams) {
            $paramsScore = config('citadel.payload.many_params_score', 15.0);
            $score += $paramsScore;
            $matches[] = 'many_parameters';
        }
        
        // Log detections if any were found
        if (!empty($matches)) {
            \Illuminate\Support\Facades\Log::debug('Citadel: PayloadAnalyzer detected suspicious patterns', [
                'ip' => $request->ip(),
                'matches' => $matches,
                'score' => $score,
                'url' => $request->fullUrl(),
            ]);
        }
        
        return $score;
    }
}