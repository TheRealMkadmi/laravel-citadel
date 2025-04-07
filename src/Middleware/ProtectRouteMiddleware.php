<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
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
     * Analyzer groups keyed by capability
     *
     * @var array<string, array<IRequestAnalyzer>>
     */
    protected array $analyzers;

    /**
     * The data store implementation.
     */
    protected DataStore $dataStore;

    /**
     * Constructor.
     *
     * @param  array<string, array<IRequestAnalyzer>>  $analyzers  Analyzers grouped by capability
     * @param  DataStore  $dataStore  DataStore implementation for caching results
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
        Log::info('Handling request in ProtectRouteMiddleware.', [
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
        ]);

        // Skip if middleware is disabled
        if (! Config::get(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true)) {
            Log::info('Middleware is disabled. Passing request through.', ['path' => $request->path()]);

            return $next($request);
        }

        // Get fingerprint - skip if not available
        $fingerprint = $request->getFingerprint();
        if (empty($fingerprint)) {
            Log::warning('No fingerprint available for request.', [
                'path' => $request->path(),
                'method' => $request->method(),
            ]);

            return $next($request);
        }

        Log::info('Fingerprint retrieved for request.', ['fingerprint' => $fingerprint]);

        // Check for existing ban
        if ($this->isBanned($fingerprint)) {
            Log::warning('Banned fingerprint attempted access.', [
                'fingerprint' => $fingerprint,
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);

            return $this->blockRequest($request);
        }

        // Get applicable analyzers for this request
        $applicableAnalyzers = $this->getApplicableAnalyzers($request);

        if (empty($applicableAnalyzers)) {
            Log::info('No applicable analyzers for request.', [
                'fingerprint' => $fingerprint,
                'path' => $request->path(),
            ]);

            return $next($request);
        }

        Log::info('Running analyzers for request.', [
            'fingerprint' => $fingerprint,
            'analyzer_count' => count($applicableAnalyzers),
        ]);

        // Run analyzers and calculate scores
        $result = $this->runAnalyzers($request, $applicableAnalyzers);

        // Check if the request should be blocked
        if ($this->shouldBlockRequest($result)) {
            Log::warning('Request blocked based on analyzer results.', [
                'fingerprint' => $fingerprint,
                'total_score' => $result['total_score'],
                'max_score' => $result['max_score'],
            ]);
            $this->processBlockedRequest($request, $result, $fingerprint);

            return $this->blockRequest($request);
        }

        Log::info('Request passed all analyzers.', [
            'fingerprint' => $fingerprint,
            'total_score' => $result['total_score'],
            'max_score' => $result['max_score'],
        ]);

        // Log suspicious activity that wasn't blocked
        $this->logSuspiciousActivity($request, $result);

        return $next($request);
    }

    /**
     * Check if a fingerprint is banned
     */
    protected function isBanned(string $fingerprint): bool
    {
        $banKey = self::BAN_KEY_PREFIX.$fingerprint;

        Log::debug('Citadel: Checking ban status', [
            'fingerprint' => $fingerprint,
            'ban_key' => $banKey,
        ]);

        $isBanned = $this->dataStore->getValue($banKey) !== null;

        if ($isBanned) {
            Log::info('Citadel: Found active ban', [
                'fingerprint' => $fingerprint,
                'data_store' => get_class($this->dataStore),
            ]);
        } else {
            Log::debug('Citadel: No ban found', [
                'fingerprint' => $fingerprint,
            ]);
        }

        return $isBanned;
    }

    /**
     * Get analyzers that should be applied to this request
     *
     * @param  Request  $request  The HTTP request
     * @return array<IRequestAnalyzer>
     */
    protected function getApplicableAnalyzers(Request $request): array
    {
        // Start with all enabled analyzers
        $allAnalyzers = $this->analyzers['all'] ?? [];

        // If external resource analyzers are disabled globally, filter them out
        if (! Config::get('citadel.external_analyzers.enabled', true)) {
            $externalResourceAnalyzers = $this->analyzers['external_resource_analyzers'] ?? [];
            $externalAnalyzerIds = array_map(fn ($analyzer) => $analyzer->getIdentifier(), $externalResourceAnalyzers);

            if (! empty($externalAnalyzerIds)) {
                Log::debug('Citadel: Skipping external resource analyzers (disabled by config)', [
                    'skipped_analyzers' => $externalAnalyzerIds,
                ]);
            }

            $allAnalyzers = array_filter($allAnalyzers, function ($analyzer) {
                return ! $analyzer->usesExternalResources();
            });
        }

        // If request has no body, filter out body analyzers
        $hasRequestBody = ! empty($request->all()) || ! empty($request->getContent());
        if (! $hasRequestBody) {
            $bodyAnalyzers = $this->analyzers['body_analyzers'] ?? [];
            $bodyAnalyzerIds = array_map(fn ($analyzer) => $analyzer->getIdentifier(), $bodyAnalyzers);

            if (! empty($bodyAnalyzerIds)) {
                Log::debug('Citadel: Skipping body analyzers (no request body)', [
                    'skipped_analyzers' => $bodyAnalyzerIds,
                ]);
            }

            $allAnalyzers = array_filter($allAnalyzers, function ($analyzer) {
                return ! $analyzer->requiresRequestBody();
            });
        }

        return $allAnalyzers;
    }

    /**
     * Run all applicable analyzers on the request and get their scores
     *
     * @param  Request  $request  The HTTP request to analyze
     * @param  array<IRequestAnalyzer>  $analyzers  The analyzers to run
     * @return array Analysis results with scores and metadata
     */
    protected function runAnalyzers(Request $request, array $analyzers): array
    {
        $scores = [];
        $fingerprint = $request->getFingerprint();
        $analyzerNames = array_map(fn ($a) => $a->getIdentifier(), $analyzers);

        Log::debug('Citadel: Running analyzers', [
            'fingerprint' => $fingerprint,
            'analyzer_count' => count($analyzers),
            'analyzers' => $analyzerNames,
            'path' => $request->path(),
            'method' => $request->method(),
        ]);

        foreach ($analyzers as $analyzer) {
            try {
                $identifier = $analyzer->getIdentifier();
                $cacheKey = self::ANALYZER_CACHE_KEY_PREFIX."{$fingerprint}:{$identifier}";
                $score = 0.0;

                $startTime = microtime(true);

                // Try to get from cache first
                $cachedScore = $this->dataStore->getValue($cacheKey);

                if ($cachedScore !== null) {
                    $score = (float) $cachedScore;
                    Log::debug('Citadel: Using cached analyzer score', [
                        'analyzer' => $identifier,
                        'score' => $score,
                        'fingerprint' => $fingerprint,
                        'cache_key' => $cacheKey,
                        'cache_hit' => true,
                    ]);
                } else {
                    // Calculate fresh score
                    Log::debug('Citadel: Cache miss for analyzer, calculating new score', [
                        'analyzer' => $identifier,
                        'fingerprint' => $fingerprint,
                        'cache_key' => $cacheKey,
                    ]);

                    $score = $analyzer->analyze($request);
                    $processingTime = microtime(true) - $startTime;

                    Log::debug('Citadel: Analyzer completed', [
                        'analyzer' => $identifier,
                        'score' => $score,
                        'processing_time_ms' => round($processingTime * 1000, 2),
                        'uses_external_resources' => $analyzer->usesExternalResources(),
                        'requires_body' => $analyzer->requiresRequestBody(),
                    ]);

                    // Cache non-zero scores
                    if ($score > 0.0) {
                        $ttl = Config::get(CitadelConfig::KEY_MIDDLEWARE_CACHE_TTL, 3600);
                        $this->dataStore->setValue($cacheKey, $score, $ttl);
                        Log::debug('Citadel: Cached analyzer score', [
                            'analyzer' => $identifier,
                            'score' => $score,
                            'ttl' => $ttl,
                            'cache_key' => $cacheKey,
                        ]);
                    }
                }

                $scores[$identifier] = $score;
            } catch (\Throwable $e) {
                // Log error but continue with other analyzers
                Log::error('Citadel: Analyzer failed', [
                    'analyzer' => $analyzer->getIdentifier(),
                    'message' => $e->getMessage(),
                    'exception' => get_class($e),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'fingerprint' => $fingerprint,
                    'path' => $request->path(),
                ]);
            }
        }

        // Calculate aggregate results
        $totalScore = array_sum($scores);
        $maxScore = ! empty($scores) ? max($scores) : 0.0;
        $maxScoringAnalyzer = array_search($maxScore, $scores, true);

        Log::info('Citadel: Score evaluation summary', [
            'total_score' => $totalScore,
            'max_score' => $maxScore,
            'max_scoring_analyzer' => $maxScoringAnalyzer,
            'fingerprint' => $fingerprint,
            'path' => $request->path(),
            'method' => $request->method(),
            'all_scores' => $scores,
            'analyzer_count' => count($analyzers),
        ]);

        return [
            'scores' => $scores,
            'total_score' => $totalScore,
            'max_score' => $maxScore,
            'max_scoring_analyzer' => $maxScoringAnalyzer,
        ];
    }

    /**
     * Determine if the request should be blocked based on analyzer scores
     *
     * @param  array  $result  The analysis results
     * @return bool Whether the request should be blocked
     */
    protected function shouldBlockRequest(array $result): bool
    {
        $thresholdScore = Config::get(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 100);

        Log::debug('Citadel: Evaluating scores against threshold', [
            'threshold_score' => $thresholdScore,
            'total_score' => $result['total_score'],
            'max_score' => $result['max_score'],
            'max_scoring_analyzer' => $result['max_scoring_analyzer'] ?? 'none',
        ]);

        $shouldBlockTotal = $result['total_score'] >= $thresholdScore;
        $shouldBlockMax = $result['max_score'] >= $thresholdScore;
        $shouldBlock = $shouldBlockTotal || $shouldBlockMax;

        if ($shouldBlock) {
            if ($shouldBlockTotal) {
                Log::info('Citadel: Request will be blocked due to high total score', [
                    'total_score' => $result['total_score'],
                    'threshold' => $thresholdScore,
                ]);
            }

            if ($shouldBlockMax) {
                Log::info('Citadel: Request will be blocked due to high individual analyzer score', [
                    'max_score' => $result['max_score'],
                    'max_analyzer' => $result['max_scoring_analyzer'] ?? 'unknown',
                    'threshold' => $thresholdScore,
                ]);
            }
        } else {
            Log::debug('Citadel: Scores below blocking threshold', [
                'total_score' => $result['total_score'],
                'max_score' => $result['max_score'],
                'threshold' => $thresholdScore,
                'score_percentage_of_threshold' => $result['max_score'] > 0 ?
                    round(($result['max_score'] / $thresholdScore) * 100, 1) : 0,
            ]);
        }

        // Block if total score or any individual score exceeds threshold
        return $shouldBlock;
    }

    /**
     * Process a request that will be blocked
     *
     * @param  Request  $request  The HTTP request
     * @param  array  $result  The analysis results
     * @param  string  $fingerprint  The request fingerprint
     */
    protected function processBlockedRequest(Request $request, array $result, string $fingerprint): void
    {
        $thresholdScore = Config::get(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 100);

        // Log detailed information about blocking
        Log::warning('Citadel: Blocking request', [
            'fingerprint' => $fingerprint,
            'total_score' => $result['total_score'],
            'max_score' => $result['max_score'],
            'threshold' => $thresholdScore,
            'triggering_analyzer' => ($result['max_score'] >= $thresholdScore)
                ? $result['max_scoring_analyzer']
                : 'combined_score',
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'all_scores' => $result['scores'] ?? [],
        ]);

        // Ban the fingerprint if configured to do so
        if (Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED, false)) {
            $banDuration = Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_DURATION, 3600);

            Log::info('Citadel: Auto-banning fingerprint based on analyzer results', [
                'fingerprint' => $fingerprint,
                'ban_duration_seconds' => $banDuration,
                'max_score' => $result['max_score'],
                'triggering_analyzer' => $result['max_scoring_analyzer'] ?? 'combined_score',
                'expires_at' => now()->addSeconds($banDuration)->toDateTimeString(),
            ]);

            $this->banFingerprint($fingerprint);
        } else {
            Log::debug('Citadel: Auto-banning is disabled, request will only be blocked once', [
                'fingerprint' => $fingerprint,
                'config_path' => CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED,
            ]);
        }

        // Check if we should also log to external systems or take additional actions
        $shouldReportSecurity = Config::get(CitadelConfig::KEY_MIDDLEWARE_REPORT_SECURITY_EVENTS, false);
        if ($shouldReportSecurity) {
            $this->reportSecurityEvent($request, $result, $fingerprint);
        }
    }

    /**
     * Report a security event to configured channels
     *
     * @param  Request  $request  The HTTP request
     * @param  array  $result  The analysis results
     * @param  string  $fingerprint  The request fingerprint
     */
    protected function reportSecurityEvent(Request $request, array $result, string $fingerprint): void
    {
        // Log with special channel for security monitoring
        Log::channel(Config::get(CitadelConfig::KEY_MIDDLEWARE_SECURITY_LOG_CHANNEL, 'stack'))
            ->critical('Citadel: Security event detected', [
                'event_type' => 'request_blocked',
                'fingerprint' => $fingerprint,
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'path' => $request->path(),
                'method' => $request->method(),
                'total_score' => $result['total_score'],
                'max_score' => $result['max_score'],
                'detected_at' => now()->toDateTimeString(),
                'triggering_analyzer' => $result['max_scoring_analyzer'] ?? 'combined_score',
                'referer' => $request->header('referer'),
                'scores' => $result['scores'] ?? [],
                'content_type' => $request->header('Content-Type'),
                'request_size' => strlen($request->getContent()),
            ]);
    }

    /**
     * Log suspicious activity that wasn't blocked
     *
     * @param  Request  $request  The HTTP request
     * @param  array  $result  The analysis results
     */
    public function logSuspiciousActivity(Request $request, array $result): void
    {
        $warningThreshold = Config::get(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 80);

        // Only log if scores are high enough to be suspicious
        if ($result['total_score'] < $warningThreshold && $result['max_score'] < $warningThreshold) {
            return;
        }

        Log::info('Citadel: Suspicious activity detected', [
            'fingerprint' => $request->getFingerprint(),
            'total_score' => $result['total_score'],
            'max_score' => $result['max_score'],
            'warning_threshold' => $warningThreshold,
            'scores' => $result['scores'],
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);
    }

    /**
     * Ban a fingerprint for the configured duration
     *
     * @param  string  $fingerprint  The fingerprint to ban
     */
    protected function banFingerprint(string $fingerprint): void
    {
        $key = self::BAN_KEY_PREFIX.$fingerprint;
        $duration = Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_DURATION, 3600);
        $this->dataStore->setValue($key, now()->timestamp, $duration);

        Log::info('Citadel: Fingerprint banned', [
            'fingerprint' => $fingerprint,
            'duration' => $duration,
        ]);
    }

    /**
     * Return a blocking response based on configuration
     *
     * @param  Request  $request  The HTTP request
     * @return mixed The response to return to the client
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
