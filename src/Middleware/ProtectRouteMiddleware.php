<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\Contracts\DataStore;

class ProtectRouteMiddleware
{
    /**
     * Collection of request analyzers
     *
     * @var array<IRequestAnalyzer>
     */
    protected array $analyzers = [];

    /**
     * The data store instance.
     *
     * @var \TheRealMkadmi\Citadel\Contracts\DataStore
     */
    protected DataStore $dataStore;

    /**
     * Suspect score threshold for blocking requests
     *
     * @var float
     */
    protected float $threshold;
    
    /**
     * Create a new middleware instance.
     *
     * @param array<IRequestAnalyzer> $analyzers
     * @param \TheRealMkadmi\Citadel\Contracts\DataStore $dataStore
     */
    public function __construct(array $analyzers = [], DataStore $dataStore)
    {
        $this->analyzers = $analyzers;
        $this->dataStore = $dataStore;
        $this->threshold = (float) config('citadel.threshold', 50.0);
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle(Request $request, \Closure $next)
    {
        // Skip analysis if no analyzers are registered
        if (empty($this->analyzers)) {
            return $next($request);
        }
        
        $fingerprint = $request->getFingerprint();
        $totalScore = 0;
        $scoreBreakdown = [];
        
        // If no fingerprint is provided, we can still analyze but will use IP for tracking
        $trackingId = $fingerprint ?? md5($request->ip() . $request->userAgent());
        
        $logContext = [
            'fingerprint' => $fingerprint ?? 'none',
            'url' => $request->fullUrl(),
            'ip' => $request->ip(),
        ];
        
        // Process each analyzer and collect scores
        foreach ($this->analyzers as $analyzer) {
            $shortName = class_basename($analyzer);
            
            try {
                // Run the analyzer
                $score = $analyzer->analyze($request);
                $totalScore += $score;
                $scoreBreakdown[$shortName] = $score;
                
                // Store analyzer result in cache with proper prefixing if we have a trackingId
                if ($trackingId) {
                    $cacheKey = $this->getCacheKey($trackingId, $shortName);
                    $ttl = config('citadel.cache.analyzer_results_ttl', 3600);
                    $this->dataStore->setValue($cacheKey, $score, $ttl);
                }
                
                // Log each analyzer's score
                Log::debug("Citadel: {$shortName} score", array_merge($logContext, [
                    'analyzer' => $shortName,
                    'score' => $score,
                ]));
                
                // Early return if we're already above the threshold
                if ($totalScore >= $this->threshold) {
                    // Track this blocked request
                    $this->trackBlockedRequest($trackingId, $totalScore, $scoreBreakdown, $shortName);
                    
                    Log::warning("Citadel: Request blocked due to high suspect score", array_merge($logContext, [
                        'total_score' => $totalScore,
                        'threshold' => $this->threshold,
                        'breakdown' => $scoreBreakdown,
                        'terminated_by' => $shortName,
                    ]));
                    
                    return response()->json([
                        'message' => trans('citadel::messages.request_blocked'),
                    ], 403);
                }
            } catch (\Throwable $e) {
                // Log errors but don't block requests due to analyzer failures
                Log::error("Citadel: Analyzer error in {$shortName}", array_merge($logContext, [
                    'analyzer' => $shortName,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]));
            }
        }
        
        // Log the final score
        Log::debug("Citadel: Final score for request", array_merge($logContext, [
            'total_score' => $totalScore,
            'threshold' => $this->threshold,
            'breakdown' => $scoreBreakdown,
            'passed' => true,
        ]));
        
        // Allow the request to proceed if the score is below the threshold
        $response = $next($request);
        
        // Update fail counters if the response indicates an error
        if ($response->getStatusCode() >= 400 && $trackingId) {
            $this->trackFailedResponse($trackingId, $response->getStatusCode());
        }
        
        return $response;
    }
    
    /**
     * Generate a cache key for analyzer results
     *
     * @param string $tracking
     * @param string $analyzerName
     * @return string
     */
    protected function getCacheKey(string $tracking, string $analyzerName): string
    {
        return Str::start("analyzer:{$analyzerName}:{$tracking}", 
            config('citadel.cache.key_prefix', 'citadel:'));
    }
    
    /**
     * Track a blocked request in the data store
     *
     * @param string $tracking
     * @param float $totalScore
     * @param array $scoreBreakdown
     * @param string $terminatedBy
     * @return void
     */
    protected function trackBlockedRequest(string $tracking, float $totalScore, array $scoreBreakdown, string $terminatedBy): void
    {
        $blockedKey = Str::start("blocked:{$tracking}", 
            config('citadel.cache.key_prefix', 'citadel:'));
        
        $ttl = config('citadel.cache.blocked_request_ttl', 86400);
        
        // Store the blocked request details
        $this->dataStore->setValue($blockedKey, [
            'timestamp' => now()->timestamp,
            'total_score' => $totalScore,
            'breakdown' => $scoreBreakdown,
            'terminated_by' => $terminatedBy,
        ], $ttl);
        
        // Increment blocked count for this tracking ID
        $blockedCountKey = Str::start("blocked:count:{$tracking}", 
            config('citadel.cache.key_prefix', 'citadel:'));
            
        if (!$this->dataStore->hasValue($blockedCountKey)) {
            $this->dataStore->setValue($blockedCountKey, 1, $ttl);
        } else {
            $this->dataStore->increment($blockedCountKey);
        }
    }
    
    /**
     * Track a failed response in the data store
     *
     * @param string $tracking
     * @param int $statusCode
     * @return void
     */
    protected function trackFailedResponse(string $tracking, int $statusCode): void
    {
        $failKey = Str::start("failed:{$tracking}", 
            config('citadel.cache.key_prefix', 'citadel:'));
        
        $ttl = config('citadel.cache.failed_request_ttl', 86400);
        
        // Store or update failed response tracking
        if (!$this->dataStore->hasValue($failKey)) {
            $this->dataStore->setValue($failKey, [
                'count' => 1,
                'codes' => [$statusCode => 1],
                'first_failure' => now()->timestamp,
                'last_failure' => now()->timestamp,
            ], $ttl);
        } else {
            $failData = $this->dataStore->getValue($failKey);
            $failData['count'] = ($failData['count'] ?? 0) + 1;
            
            if (!isset($failData['codes'])) {
                $failData['codes'] = [];
            }
            
            $failData['codes'][$statusCode] = ($failData['codes'][$statusCode] ?? 0) + 1;
            $failData['last_failure'] = now()->timestamp;
            $this->dataStore->setValue($failKey, $failData, $ttl);
        }
    }
}