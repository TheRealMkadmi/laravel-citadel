<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\ResponseType;

class ProtectRouteMiddleware
{
    /**
     * Constants for key prefixes
     */
    private const BAN_KEY_PREFIX = 'ban:';
    private const ANALYZER_CACHE_KEY_PREFIX = 'analyzer:';

    /**
     * Middleware group identifiers
     */
    private const MIDDLEWARE_GROUP_ACTIVE = 'citadel-active';
    private const MIDDLEWARE_GROUP_PASSIVE = 'citadel-passive';

    /**
     * Analyzers grouped by capability.
     *
     * @var array<string, array<IRequestAnalyzer>>
     */
    protected array $analyzers;

    /**
     * The data store implementation.
     */
    protected DataStore $dataStore;

    /**
     * Create a new middleware instance.
     *
     * @param  array<string, array<IRequestAnalyzer>>  $analyzers  The analyzers grouped by capability
     * @param  DataStore  $dataStore  The data store implementation
     */
    public function __construct(array $analyzers, DataStore $dataStore)
    {
        $this->analyzers = $analyzers;
        $this->dataStore = $dataStore;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        // Skip if middleware is disabled
        if (!Config::get(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true)) {
            return $next($request);
        }

        // Get fingerprint - skip if not available
        $fingerprint = $request->getFingerprint();
        if (empty($fingerprint)) {
            Log::debug('Citadel: No fingerprint available for request', [
                'path' => $request->path(),
                'method' => $request->method()
            ]);
            return $next($request);
        }

        // Check for existing ban
        if ($this->isBanned($fingerprint)) {
            Log::info('Citadel: Banned fingerprint attempted access', [
                'fingerprint' => $fingerprint,
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);
            return $this->blockRequest($request);
        }

        // Get applicable analyzers for this request
        $applicableAnalyzers = $this->getApplicableAnalyzers($request);
        
        if (empty($applicableAnalyzers)) {
            Log::debug('Citadel: No applicable analyzers for request', [
                'fingerprint' => $fingerprint,
                'path' => $request->path()
            ]);
            return $next($request);
        }

        // Run analyzers and evaluate results
        $result = $this->runAnalyzers($request, $applicableAnalyzers);
        
        // Determine if request should be blocked based on scores
        if ($this->shouldBlockRequest($request, $result)) {
            $this->processBlockedRequest($request, $result, $fingerprint);
            return $this->blockRequest($request);
        }

        // Log suspicious activity that wasn't blocked
        $this->logSuspiciousActivity($request, $result);
        
        return $next($request);
    }

    /**
     * Check if a fingerprint is banned
     */
    protected function isBanned(string $fingerprint): bool
    {
        $banKey = self::BAN_KEY_PREFIX . $fingerprint;
        return $this->dataStore->getValue($banKey) !== null;
    }

    /**
     * Get analyzers applicable to this request based on request characteristics
     * 
     * @param Request $request
     * @return array<IRequestAnalyzer>
     */
    protected function getApplicableAnalyzers(Request $request): array
    {
        // Start with all enabled analyzers
        $allAnalyzers = $this->analyzers['all'] ?? [];
        
        // Filter out analyzers that require a request body if the request has none
        $hasRequestBody = !empty($request->all()) || !empty($request->getContent());
        
        return array_filter($allAnalyzers, function(IRequestAnalyzer $analyzer) use ($hasRequestBody) {
            // Skip analyzers that require request body when none exists
            if ($analyzer->requiresRequestBody() && !$hasRequestBody) {
                return false;
            }
            
            // Skip external resource analyzers if globally disabled
            if ($analyzer->usesExternalResources() && 
                !Config::get('citadel.external_analyzers.enabled', true)) {
                return false;
            }
            
            return true;
        });
    }
    
    /**
     * Run all applicable analyzers on the request and get their scores
     * 
     * @param Request $request The HTTP request to analyze
     * @param array<IRequestAnalyzer> $analyzers The analyzers to run
     * @return array Analysis results with scores and metadata
     */
    protected function runAnalyzers(Request $request, array $analyzers): array
    {
        $scores = [];
        $fingerprint = $request->getFingerprint();
        $analyzerNames = array_map(fn($a) => $a->getIdentifier(), $analyzers);
        
        Log::debug('Citadel: Running analyzers', [
            'fingerprint' => $fingerprint,
            'analyzerCount' => count($analyzers),
            'analyzerNames' => $analyzerNames
        ]);
        
        foreach ($analyzers as $analyzer) {
            try {
                $identifier = $analyzer->getIdentifier();
                $cacheKey = $this->getCacheKey($fingerprint, $identifier);
                $score = 0.0;
                
                // Try to get from cache first
                $cachedScore = $this->dataStore->getValue($cacheKey);
                
                if ($cachedScore !== null) {
                    $score = (float)$cachedScore;
                    Log::debug('Citadel: Using cached score', [
                        'analyzer' => $identifier,
                        'fingerprint' => $fingerprint,
                        'score' => $score
                    ]);
                } else {
                    // Calculate fresh score
                    $score = $analyzer->analyze($request);
                    
                    // Cache non-zero scores
                    if ($score > 0.0) {
                        $ttl = Config::get(CitadelConfig::KEY_MIDDLEWARE_CACHE_TTL, 3600);
                        $this->dataStore->setValue($cacheKey, $score, $ttl);
                        Log::debug('Citadel: Calculated and cached score', [
                            'analyzer' => $identifier,
                            'fingerprint' => $fingerprint,
                            'score' => $score,
                            'ttl' => $ttl
                        ]);
                    } else {
                        Log::debug('Citadel: Calculated score', [
                            'analyzer' => $identifier,
                            'fingerprint' => $fingerprint,
                            'score' => $score
                        ]);
                    }
                }
                
                $scores[$identifier] = $score;
            } catch (\Exception $e) {
                // Log error but continue with other analyzers
                Log::error('Citadel: Analyzer error', [
                    'analyzer' => $analyzer->getIdentifier(),
                    'fingerprint' => $fingerprint,
                    'message' => $e->getMessage(),
                    'exception' => get_class($e)
                ]);
            }
        }
        
        // Calculate aggregate results
        $totalScore = array_sum($scores);
        $maxScore = !empty($scores) ? max($scores) : 0.0;
        $maxScoringAnalyzer = array_search($maxScore, $scores, true);
        
        Log::debug('Citadel: Score evaluation complete', [
            'fingerprint' => $fingerprint,
            'totalScore' => $totalScore,
            'maxScore' => $maxScore,
            'maxScoringAnalyzer' => $maxScoringAnalyzer,
            'allScores' => $scores
        ]);
        
        return [
            'scores' => $scores,
            'totalScore' => $totalScore,
            'maxScore' => $maxScore,
            'maxScoringAnalyzer' => $maxScoringAnalyzer
        ];
    }
    
    /**
     * Determine if the request should be blocked based on analyzer scores
     */
    protected function shouldBlockRequest(Request $request, array $result): bool
    {
        // Only block requests when using active middleware
        if (!$this->isActiveMiddleware($request)) {
            return false;
        }
        
        $thresholdScore = Config::get(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 100);
        
        // Block if total score or any individual score exceeds threshold
        return $result['totalScore'] >= $thresholdScore || $result['maxScore'] >= $thresholdScore;
    }
    
    /**
     * Process a request that will be blocked
     */
    protected function processBlockedRequest(Request $request, array $result, string $fingerprint): void
    {
        $thresholdScore = Config::get(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 100);
        
        // Log detailed information about blocking
        Log::warning('Citadel: Blocking request', [
            'fingerprint' => $fingerprint,
            'totalScore' => $result['totalScore'],
            'maxScore' => $result['maxScore'],
            'threshold' => $thresholdScore,
            'triggeringAnalyzer' => ($result['maxScore'] >= $thresholdScore) 
                ? $result['maxScoringAnalyzer'] 
                : 'combinedScore',
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'userAgent' => $request->userAgent()
        ]);
        
        // Ban the fingerprint if configured to do so
        if (Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED, false)) {
            $this->banFingerprint($fingerprint);
        }
    }
    
    /**
     * Log suspicious activity that wasn't blocked
     */
    protected function logSuspiciousActivity(Request $request, array $result): void
    {
        $warningThreshold = Config::get(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 80);
        
        // Only log if scores are high enough to be suspicious
        if ($result['totalScore'] < $warningThreshold && $result['maxScore'] < $warningThreshold) {
            return;
        }
        
        $isActiveMode = $this->isActiveMiddleware($request);
        $logLevel = $isActiveMode ? 'info' : 'debug';
        $modePrefix = $isActiveMode ? '' : '(Passive) ';
        
        Log::log($logLevel, "Citadel: {$modePrefix}Suspicious activity detected", [
            'fingerprint' => $request->getFingerprint(),
            'totalScore' => $result['totalScore'],
            'maxScore' => $result['maxScore'],
            'warningThreshold' => $warningThreshold,
            'scores' => $result['scores'],
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'userAgent' => $request->userAgent()
        ]);
    }

    /**
     * Check if the current request is using the active middleware group
     */
    protected function isActiveMiddleware(Request $request): bool
    {
        $route = $request->route();
        if (!$route) {
            return false;
        }
        
        $middleware = $route->gatherMiddleware();
        
        foreach ($middleware as $middlewareItem) {
            if (Str::startsWith($middlewareItem, self::MIDDLEWARE_GROUP_ACTIVE)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Generate a cache key for analyzer results
     */
    protected function getCacheKey(string $fingerprint, string $analyzerIdentifier): string
    {
        return self::ANALYZER_CACHE_KEY_PREFIX . "{$fingerprint}:{$analyzerIdentifier}";
    }

    /**
     * Ban a fingerprint for the configured duration
     */
    protected function banFingerprint(string $fingerprint): void
    {
        $key = self::BAN_KEY_PREFIX . $fingerprint;
        $duration = Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_DURATION, 3600);
        $this->dataStore->setValue($key, now()->timestamp, $duration);
        
        Log::info('Citadel: Fingerprint banned', [
            'fingerprint' => $fingerprint,
            'duration' => $duration
        ]);
    }

    /**
     * Return a blocking response based on configuration
     */
    protected function blockRequest(Request $request): mixed
    {
        $responseCode = Config::get(CitadelConfig::KEY_RESPONSE_CODE, 403);
        $responseMessage = Config::get(CitadelConfig::KEY_RESPONSE_MESSAGE, 'Access denied');
        $responseView = Config::get(CitadelConfig::KEY_RESPONSE_VIEW);
        $responseTypeStr = Config::get(CitadelConfig::KEY_RESPONSE_TYPE, ResponseType::TEXT->value);
        $responseType = ResponseType::fromString($responseTypeStr);

        return match ($responseType) {
            ResponseType::JSON => response()->json(['error' => $responseMessage], $responseCode),
            ResponseType::VIEW => $responseView 
                ? response()->view($responseView, ['message' => $responseMessage], $responseCode)
                : response($responseMessage, $responseCode),
            default => response($responseMessage, $responseCode),
        };
    }
}
