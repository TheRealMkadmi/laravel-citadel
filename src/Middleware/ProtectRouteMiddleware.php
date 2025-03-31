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
use TheRealMkadmi\Citadel\Enums\AnalyzerType;
use TheRealMkadmi\Citadel\Enums\ResponseType;

class ProtectRouteMiddleware
{
    /**
     * Ban key prefix.
     */
    private const BAN_KEY_PREFIX = 'ban:';

    /**
     * Analyzer cache key prefix.
     */
    private const ANALYZER_CACHE_KEY_PREFIX = 'analyzer:';

    /**
     * Middleware group identifiers
     */
    private const MIDDLEWARE_GROUP_ACTIVE = 'citadel-active';
    private const MIDDLEWARE_GROUP_PASSIVE = 'citadel-passive';

    /**
     * Analyzers grouped by type.
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
     * @param  array<string, array<IRequestAnalyzer>>  $analyzers  The analyzers grouped by type
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
        // Skip all checks if middleware is disabled or global protection is disabled
        if (! Config::get(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true)) {
            return $next($request);
        }

        // Get fingerprint - if not present, allow request to proceed
        $fingerprint = $request->getFingerprint();
        if (! $fingerprint) {
            return $next($request);
        }

        // Check if there's a ban record for this fingerprint
        $banKey = self::BAN_KEY_PREFIX.$fingerprint;
        if ($this->dataStore->getValue($banKey) !== null) {
            Log::info('Banned fingerprint {fingerprint} attempted to access {path}', [
                'fingerprint' => $fingerprint,
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);

            return $this->blockRequest($request);
        }

        // Determine which analyzers to use based on the current route middleware
        $applicableAnalyzers = $this->getAnalyzersByMiddlewareGroup($request);

        // Get analyzers applicable for the request characteristics
        $applicableAnalyzers = $this->filterApplicableAnalyzers($request, $applicableAnalyzers);

        // Skip if no analyzers are applicable
        if (empty($applicableAnalyzers)) {
            Log::debug('Citadel Middleware: No applicable analyzers for request', [
                'fingerprint' => $fingerprint,
                'path' => $request->path()
            ]);
            return $next($request);
        }

        // Run applicable analyzers and get results
        $analysisResult = $this->runAnalyzers($request, $applicableAnalyzers);
        $scores = collect($analysisResult['scores']);
        $totalScore = $analysisResult['totalScore'];

        // The threshold score for blocking requests
        $thresholdScore = Config::get(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 100);
        
        // Find the maximum individual analyzer score
        $maxIndividualScore = $scores->max();
        $maxScoringAnalyzer = $scores->filter(fn($value) => $value == $maxIndividualScore)->keys()->first();
        
        // Log detailed score information for testing/debugging
        Log::debug('Citadel Middleware: Score evaluation', [
            'fingerprint' => $fingerprint,
            'totalScore' => $totalScore,
            'maxIndividualScore' => $maxIndividualScore,
            'maxScoringAnalyzer' => $maxScoringAnalyzer,
            'thresholdScore' => $thresholdScore,
            'allScores' => $scores->toArray()
        ]);

        // Check if we're in active mode
        $isInActiveMode = $this->isActiveMiddleware($request);
        
        // Only block requests when using active middleware
        if ($isInActiveMode && ($totalScore >= $thresholdScore || $maxIndividualScore >= $thresholdScore)) {
            // Log detailed information about the blocking
            $this->logBlocking($request, $scores->toArray(), $totalScore, $thresholdScore);

            // Ban if enabled
            if (Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED, false)) {
                $this->banFingerprint($fingerprint);
            }

            Log::warning('Citadel Middleware: Blocking request due to high scores', [
                'fingerprint' => $fingerprint,
                'threshold' => $thresholdScore,
                'totalScore' => $totalScore, 
                'maxIndividualScore' => $maxIndividualScore,
                'triggeringAnalyzer' => ($maxIndividualScore >= $thresholdScore) ? $maxScoringAnalyzer : 'combinedScore'
            ]);

            return $this->blockRequest($request);
        }

        // Log scores for suspicious requests (even if below threshold or in passive mode)
        $warningThreshold = Config::get(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 80);
        if ($totalScore >= $warningThreshold || $maxIndividualScore >= $warningThreshold) {
            if ($isInActiveMode) {
                $this->logWarning($request, $scores->toArray(), $totalScore);
            } else {
                $this->logPassiveWarning($request, $scores->toArray(), $totalScore);
            }
        }

        // Request passed all checks or we're in passive mode, proceed with the request
        return $next($request);
    }

    /**
     * Determine which analyzers to use based on the middleware group
     * 
     * @param Request $request
     * @return array<IRequestAnalyzer>
     */
    protected function getAnalyzersByMiddlewareGroup(Request $request): array
    {
        if ($this->isActiveMiddleware($request)) {
            // Active middleware includes both active and passive analyzers
            return array_merge(
                $this->analyzers[AnalyzerType::ACTIVE->value] ?? [],
                $this->analyzers[AnalyzerType::PASSIVE->value] ?? []
            );
        } else {
            // Passive middleware only includes passive analyzers
            return $this->analyzers[AnalyzerType::PASSIVE->value] ?? [];
        }
    }
    
    /**
     * Check if the current request is using the active middleware group
     *
     * @param Request $request
     * @return bool
     */
    protected function isActiveMiddleware(Request $request): bool
    {
        // Get current middleware groups for the route
        $route = $request->route();
        if (!$route) {
            return false;
        }
        
        $middleware = $route->gatherMiddleware();
        
        // Check if the active middleware group is applied
        foreach ($middleware as $middlewareItem) {
            if (Str::startsWith($middlewareItem, self::MIDDLEWARE_GROUP_ACTIVE)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Filter analyzers applicable to the current request based on its characteristics
     *
     * @param  Request  $request  The HTTP request
     * @param  array<IRequestAnalyzer>  $analyzers  The analyzers to filter
     * @return array<IRequestAnalyzer>
     */
    protected function filterApplicableAnalyzers(Request $request, array $analyzers): array
    {
        return collect($analyzers)
            ->filter(function ($analyzer) use ($request) {
                // If analyzer scans payload, only include it when there's a body to scan
                if ($analyzer->scansPayload()) {
                    // Check if request has any content
                    $hasBody = ! empty($request->all()) || ! empty($request->getContent());

                    return $hasBody;
                }

                // Include all other analyzers
                return true;
            })
            ->values()
            ->all();
    }

    /**
     * Run all applicable analyzers on the request and calculate total score
     *
     * @param  Request  $request  The HTTP request
     * @param  array  $analyzers  List of analyzers to run
     * @return array Analysis results including scores and total
     */
    protected function runAnalyzers(Request $request, array $analyzers): array
    {
        $scores = collect();
        $fingerprint = $request->getFingerprint(); // Get fingerprint once

        Log::debug('Citadel Middleware: Running analyzers', [
            'fingerprint' => $fingerprint,
            'analyzerCount' => count($analyzers),
            'analyzerNames' => collect($analyzers)->map(fn($a) => class_basename($a))->toArray()
        ]);

        // Run analyzers and collect their scores
        foreach ($analyzers as $analyzer) {
            try {
                $analyzerName = class_basename($analyzer);
                $score = 0.0; // Initialize score
                
                // Try to get from cache first
                $cacheKey = $this->getCacheKey($fingerprint, $analyzerName);
                $cachedScore = $this->dataStore->getValue($cacheKey);

                if ($cachedScore !== null) {
                    $score = (float) $cachedScore;
                    Log::debug('Citadel Middleware: Used cached score for analyzer', [
                        'analyzer' => $analyzerName, 
                        'fingerprint' => $fingerprint, 
                        'score' => $score
                    ]);
                } else {
                    // No cache hit, calculate fresh score
                    $score = $analyzer->analyze($request);
                    
                    // Store score in cache if non-zero
                    if ($score > 0.0) {
                        $ttl = Config::get(CitadelConfig::KEY_MIDDLEWARE_CACHE_TTL, 3600);
                        $this->dataStore->setValue($cacheKey, $score, $ttl);
                        Log::debug('Citadel Middleware: Calculated and cached score for analyzer', [
                            'analyzer' => $analyzerName, 
                            'fingerprint' => $fingerprint, 
                            'score' => $score, 
                            'ttl' => $ttl
                        ]);
                    } else {
                        Log::debug('Citadel Middleware: Calculated fresh score for analyzer', [
                            'analyzer' => $analyzerName, 
                            'fingerprint' => $fingerprint, 
                            'score' => $score
                        ]);
                    }
                }
                
                // Store the score regardless of how it was obtained
                $scores->put($analyzerName, $score);

            } catch (\Exception $e) {
                // Log analyzer errors but continue with others
                Log::error('Citadel analyzer error: {message}', [
                    'message' => $e->getMessage(),
                    'analyzer' => class_basename($analyzer),
                    'tracking_id' => $fingerprint,
                    'exception' => $e,
                ]);
            }
        }

        // Calculate total score from all analyzers
        $totalScore = $scores->sum();
        
        Log::debug('Citadel Middleware: Calculated total score', [
            'fingerprint' => $fingerprint, 
            'scores' => $scores->toArray(), 
            'analyzers_count' => count($analyzers),
            'scores_count' => $scores->count(),
            'totalScore' => $totalScore
        ]);

        return [
            'scores' => $scores->toArray(),
            'totalScore' => $totalScore,
        ];
    }

    /**
     * Generate a cache key for analyzer results
     */
    protected function getCacheKey(string $tracking, string $analyzerName): string
    {
        // Create a consistent key using tracking ID and analyzer name
        return self::ANALYZER_CACHE_KEY_PREFIX."{$tracking}:{$analyzerName}";
    }

    /**
     * Ban a fingerprint for the configured duration.
     */
    protected function banFingerprint(string $fingerprint): void
    {
        $key = self::BAN_KEY_PREFIX.$fingerprint;
        $duration = Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_DURATION, 3600);
        $this->dataStore->setValue($key, now()->timestamp, $duration);
    }

    /**
     * Log when a request is blocked due to suspicion.
     */
    protected function logBlocking(Request $request, array $scores, float $totalScore, float $threshold): void
    {
        Log::warning('Citadel: Request blocked due to suspicious activity', [
            'tracking_id' => $request->getFingerprint(),
            'scores' => $scores,
            'total_score' => $totalScore,
            'threshold' => $threshold,
            'ip' => $request->ip(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
        ]);
    }

    /**
     * Log a warning for suspicious requests that aren't blocked.
     */
    protected function logWarning(Request $request, array $scores, float $totalScore): void
    {
        Log::info('Citadel: Suspicious activity detected', [
            'tracking_id' => $request->getFingerprint(),
            'scores' => $scores,
            'total_score' => $totalScore,
            'ip' => $request->ip(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
        ]);
    }
    
    /**
     * Log a warning for suspicious requests detected in passive mode.
     */
    protected function logPassiveWarning(Request $request, array $scores, float $totalScore): void
    {
        Log::info('Citadel (Passive): Suspicious activity detected', [
            'tracking_id' => $request->getFingerprint(),
            'scores' => $scores,
            'total_score' => $totalScore,
            'ip' => $request->ip(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
        ]);
    }

    /**
     * Block the request with appropriate response.
     */
    protected function blockRequest(Request $request): mixed
    {
        // Get response settings from config
        $responseCode = Config::get(CitadelConfig::KEY_RESPONSE_CODE, 403);
        $responseMessage = Config::get(CitadelConfig::KEY_RESPONSE_MESSAGE, 'Access denied');
        $responseView = Config::get(CitadelConfig::KEY_RESPONSE_VIEW);

        // Get response type from config, using the ResponseType enum
        $responseTypeStr = Config::get(CitadelConfig::KEY_RESPONSE_TYPE, ResponseType::TEXT->value);
        $responseType = ResponseType::fromString($responseTypeStr);

        // Return response based on configured type
        return match ($responseType) {
            ResponseType::JSON => response()->json(['error' => $responseMessage], $responseCode),
            ResponseType::VIEW => $responseView ? response()->view($responseView, ['message' => $responseMessage], $responseCode)
                                               : response($responseMessage, $responseCode),
            default => response($responseMessage, $responseCode),
        };
    }
}
