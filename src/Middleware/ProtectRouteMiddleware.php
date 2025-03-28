<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\DataStore\DataStore;

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
     */
    protected DataStore $dataStore;

    /**
     * Suspect score threshold for blocking requests
     */
    protected float $threshold;

    /**
     * Create a new middleware instance.
     *
     * @param  array<IRequestAnalyzer>  $analyzers
     */
    public function __construct(array $analyzers, DataStore $dataStore)
    {
        $this->analyzers = $analyzers;
        $this->dataStore = $dataStore;
        $this->threshold = (float) config('citadel.threshold', 50.0);
    }

    /**
     * Handle an incoming request.
     *
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
        $trackingId = $fingerprint ?? md5($request->ip().$request->userAgent());

        $logContext = [
            'fingerprint' => $fingerprint ?? 'none',
            'url' => $request->fullUrl(),
            'ip' => $request->ip(),
        ];

        // Check if there's a failure score from previous requests that should be incorporated
        $failureScoreKey = Str::start("fw:{$trackingId}:failureScore",
            config('citadel.cache.key_prefix', 'citadel:'));

        if ($this->dataStore->hasValue($failureScoreKey)) {
            $failureScore = (float) $this->dataStore->getValue($failureScoreKey, 0);
            $totalScore += $failureScore;
            $scoreBreakdown['FailureHistory'] = $failureScore;

            Log::debug(trans('citadel::logging.failure_history_added'), array_merge($logContext, [
                'failure_score' => $failureScore,
                'updated_total' => $totalScore,
            ]));
        }

        // Filter analyzers based on request method
        $applicableAnalyzers = $this->getApplicableAnalyzers($request);

        // Process each applicable analyzer and collect scores
        foreach ($applicableAnalyzers as $analyzer) {
            $shortName = class_basename($analyzer);

            try {
                // Run the analyzer
                $score = $analyzer->analyze($request);
                $totalScore += $score;
                $scoreBreakdown[$shortName] = $score;

                // Store analyzer result in cache with proper prefixing if we have a trackingId
                if ($trackingId) {
                    $cacheKey = $this->getCacheKey($trackingId, $shortName);
                    $ttl = (int) config('citadel.cache.analyzer_results_ttl', 3600);
                    $this->dataStore->setValue($cacheKey, $score, $ttl);
                }

                // Log each analyzer's score
                Log::debug("Citadel: {$shortName} score", array_merge($logContext, [
                    'analyzer' => $shortName,
                    'score' => $score,
                ]));

                // Early return if we're already above the threshold
                if ($totalScore >= $this->threshold) {
                    // The actual tracking of this blocked request is now handled in PostProtectRouteMiddleware
                    Log::warning(trans('citadel::logging.request_blocked'), array_merge($logContext, [
                        'total_score' => $totalScore,
                        'threshold' => $this->threshold,
                        'breakdown' => $scoreBreakdown,
                        'terminated_by' => $shortName,
                    ]));

                    return response()->json([
                        'message' => trans('citadel::messages.request_blocked'),
                        'citadel' => true,
                        'request_blocked' => true,
                    ], 403);
                }
            } catch (\Throwable $e) {
                // Log errors but don't block requests due to analyzer failures
                Log::error(trans('citadel::logging.analyzer_error', ['analyzer' => $shortName]), array_merge($logContext, [
                    'analyzer' => $shortName,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]));
            }
        }

        // Log the final score
        Log::debug(trans('citadel::logging.final_score'), array_merge($logContext, [
            'total_score' => $totalScore,
            'threshold' => $this->threshold,
            'breakdown' => $scoreBreakdown,
            'passed' => true,
        ]));

        // Allow the request to proceed if the score is below the threshold
        return $next($request);
    }

    /**
     * Get analyzers applicable to the current request based on whether it has a body
     *
     * @return array<IRequestAnalyzer>
     */
    protected function getApplicableAnalyzers(Request $request): array
    {
        return collect($this->analyzers)->filter(function ($analyzer) use ($request) {
            // Special handling for PayloadAnalyzer and SpamminessAnalyzer:
            // Only run them if the request has a body
            if ($analyzer instanceof PayloadAnalyzer ||
                $analyzer instanceof SpamminessAnalyzer) {

                // Check if request has any content
                $hasBody = ! empty($request->all()) || ! empty($request->getContent());

                // Skip these analyzers for requests without a body
                if (! $hasBody) {
                    return false;
                }
            }

            // Include all other analyzers
            return true;
        })->values()->all();
    }

    /**
     * Generate a cache key for analyzer results
     */
    protected function getCacheKey(string $tracking, string $analyzerName): string
    {
        return Str::start("analyzer:{$analyzerName}:{$tracking}",
            config('citadel.cache.key_prefix', 'citadel:'));
    }
}
