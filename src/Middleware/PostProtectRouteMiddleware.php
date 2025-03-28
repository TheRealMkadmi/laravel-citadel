<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class PostProtectRouteMiddleware
{
    /**
     * Analyzers to run on the request.
     *
     * @var array<IRequestAnalyzer>
     */
    protected array $analyzers;

    /**
     * The data store implementation.
     */
    protected DataStore $dataStore;

    /**
     * Create a new middleware instance.
     *
     * @param  array<IRequestAnalyzer>  $analyzers  The analyzers to run
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
        // Get the response first - this is passive monitoring
        $response = $next($request);

        // Skip if passive monitoring is disabled
        if (! Config::get(CitadelConfig::KEY_MIDDLEWARE_PASSIVE_ENABLED, true)) {
            return $response;
        }

        // Get fingerprint - if not present, track as anonymous
        $fingerprint = $request->getFingerprint() ?? 'anonymous';

        // Get applicable analyzers based on request characteristics
        $applicableAnalyzers = $this->getApplicableAnalyzers($request);

        // Skip if no analyzers are applicable
        if (empty($applicableAnalyzers)) {
            return $response;
        }

        // Run applicable analyzers and get results - only for logging
        try {
            $analysisResult = $this->runAnalyzers($request, $applicableAnalyzers);
            $scores = collect($analysisResult['scores']);
            $totalScore = $scores->sum();

            // Log scores for suspicious requests (even if below threshold)
            $warningThreshold = Config::get(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 80);
            if ($totalScore > $warningThreshold) {
                $this->logWarning($request, $scores->toArray(), $totalScore);
            }
        } catch (\Exception $e) {
            // Log error but don't block the request
            Log::error('Citadel error in passive monitoring: {message}', [
                'message' => $e->getMessage(),
                'tracking_id' => $fingerprint,
                'exception' => $e,
            ]);
        }

        // Return the original response - never blocks
        return $response;
    }

    /**
     * Get analyzers applicable to the current request based on its characteristics
     *
     * @param  Request  $request  The HTTP request
     * @return array<IRequestAnalyzer>
     */
    protected function getApplicableAnalyzers(Request $request): array
    {
        return collect($this->analyzers)
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

        // Run analyzers and collect their scores
        foreach ($analyzers as $analyzer) {
            try {
                $analyzerName = class_basename($analyzer);
                $score = $analyzer->analyze($request);

                // Store the score for logging only
                $scores->put($analyzerName, $score);
            } catch (\Exception $e) {
                // Log analyzer errors but continue with others
                Log::error('Citadel analyzer error in passive monitoring: {message}', [
                    'message' => $e->getMessage(),
                    'analyzer' => class_basename($analyzer),
                    'tracking_id' => $request->getFingerprint(),
                    'exception' => $e,
                ]);
            }
        }

        return [
            'scores' => $scores->toArray(),
            'totalScore' => $scores->sum(),
        ];
    }

    /**
     * Log a warning for suspicious requests that aren't blocked.
     */
    protected function logWarning(Request $request, array $scores, float $totalScore): void
    {
        Log::info('Citadel (Passive): Suspicious activity detected', [
            'tracking_id' => $request->getFingerprint() ?? 'anonymous',
            'scores' => $scores,
            'total_score' => $totalScore,
            'ip' => $request->ip(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
        ]);
    }
}
