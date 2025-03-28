<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class ProtectRouteMiddleware
{
    /**
     * Configuration keys.
     */
    private const CONFIG_KEY_MIDDLEWARE = 'citadel.middleware';
    private const CONFIG_KEY_ACTIVE_ENABLED = 'citadel.middleware.active_enabled'; 
    private const CONFIG_KEY_ENABLED = 'citadel.middleware.enabled';
    private const CONFIG_KEY_THRESHOLD_SCORE = 'citadel.middleware.threshold_score';
    private const CONFIG_KEY_WARNING_THRESHOLD = 'citadel.middleware.warning_threshold';
    private const CONFIG_KEY_BAN_ENABLED = 'citadel.middleware.ban_enabled';
    private const CONFIG_KEY_BAN_DURATION = 'citadel.middleware.ban_duration';
    private const CONFIG_KEY_CACHE_TTL = 'citadel.middleware.cache_ttl';
    private const CONFIG_KEY_BLOCK_RESPONSE = 'citadel.middleware.block_response';
    private const CONFIG_KEY_RESPONSE_TYPE = 'citadel.middleware.block_response.type';
    private const CONFIG_KEY_RESPONSE_CODE = 'citadel.middleware.block_response.code';
    private const CONFIG_KEY_RESPONSE_MESSAGE = 'citadel.middleware.block_response.message';
    private const CONFIG_KEY_RESPONSE_VIEW = 'citadel.middleware.block_response.view';

    /**
     * Ban key prefix.
     */
    private const BAN_KEY_PREFIX = 'ban:';
    
    /**
     * Analyzer cache key prefix.
     */
    private const ANALYZER_CACHE_KEY_PREFIX = 'analyzer:';

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
     *
     * @param  \Illuminate\Http\Request  $request  The HTTP request
     * @param  \Closure  $next  The next middleware
     * @return mixed The HTTP response
     */
    public function handle(Request $request, Closure $next)
    {
        // If middleware is disabled (globally or active specifically), just pass through
        if (!Config::get(self::CONFIG_KEY_ENABLED, true) || 
            !Config::get(self::CONFIG_KEY_ACTIVE_ENABLED, true)) {
            return $next($request);
        }

        // Get the user's fingerprint
        $tracking = $request->getFingerprint();

        // Check if the fingerprint is banned
        if ($this->isBanned($tracking)) {
            return $this->blockResponse($request);
        }

        // Skip analysis if no analyzers are registered
        if (empty($this->analyzers)) {
            return $next($request);
        }

        // Get applicable analyzers based on request characteristics
        $applicableAnalyzers = $this->getApplicableAnalyzers($request);

        // Skip if no applicable analyzers
        if (empty($applicableAnalyzers)) {
            return $next($request);
        }

        // Run all applicable analyzers
        $analysisResults = $this->runAnalyzers($request, $applicableAnalyzers);
        $totalScore = $analysisResults['totalScore'];
        $scores = $analysisResults['scores'];

        // Check if the score exceeds the threshold
        $thresholdScore = Config::get(self::CONFIG_KEY_THRESHOLD_SCORE, 100);
        if ($totalScore > $thresholdScore) {
            // Ban the fingerprint if ban_enabled is true
            if (Config::get(self::CONFIG_KEY_BAN_ENABLED, true)) {
                $this->banFingerprint($tracking);
            }

            // Log the block
            $this->logBlock($request, $tracking, $totalScore, $thresholdScore);

            // Return a response that blocks the request
            return $this->blockResponse($request);
        }

        // Log scores for suspicious requests (even if below threshold)
        $warningThreshold = Config::get(self::CONFIG_KEY_WARNING_THRESHOLD, 80);
        if ($totalScore > $warningThreshold) {
            $this->logWarning($request, $scores, $totalScore);
        }

        // Request passed all checks, proceed
        return $next($request);
    }

    /**
     * Get analyzers applicable to the current request based on its characteristics
     *
     * @param Request $request The HTTP request
     * @return array<IRequestAnalyzer>
     */
    protected function getApplicableAnalyzers(Request $request): array
    {
        return collect($this->analyzers)
            ->filter(function ($analyzer) use ($request) {
                // If analyzer scans payload, only include it when there's a body to scan
                if ($analyzer->scansPayload()) {
                    // Check if request has any content
                    $hasBody = !empty($request->all()) || !empty($request->getContent());
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
     * @param Request $request The HTTP request
     * @param array $analyzers List of analyzers to run
     * @return array Analysis results including scores and total
     */
    protected function runAnalyzers(Request $request, array $analyzers): array
    {
        $scores = collect();
        
        // Run analyzers and collect their scores
        foreach ($analyzers as $analyzer) {
            try {
                $analyzerName = class_basename($analyzer);
                
                // Get cache key for analyzer results
                $cacheKey = $this->getCacheKey($request->getFingerprint(), $analyzerName);
                
                // Try to get cached result
                $cachedScore = $this->dataStore->getValue($cacheKey);
                $score = $cachedScore !== null ? (float) $cachedScore : $analyzer->analyze($request);
                
                // Cache the score if not already cached
                if ($cachedScore === null) {
                    // Get configurable cache TTL for analyzer results, default to 1 hour
                    $ttl = Config::get(self::CONFIG_KEY_CACHE_TTL, 3600);
                    $this->dataStore->setValue($cacheKey, $score, $ttl);
                }
                
                // Store the score
                $scores->put($analyzerName, $score);
                
            } catch (\Exception $e) {
                // Log analyzer errors but continue with others
                Log::error('Citadel analyzer error: {message}', [
                    'message' => $e->getMessage(),
                    'analyzer' => class_basename($analyzer),
                    'tracking_id' => $request->getFingerprint(),
                    'exception' => $e,
                ]);
            }
        }

        return [
            'scores' => $scores->toArray(),
            'totalScore' => $scores->sum()
        ];
    }

    /**
     * Generate a cache key for analyzer results
     */
    protected function getCacheKey(string $tracking, string $analyzerName): string
    {
        // Create a consistent key using tracking ID and analyzer name
        return self::ANALYZER_CACHE_KEY_PREFIX . "{$tracking}:{$analyzerName}";
    }

    /**
     * Check if a fingerprint is banned.
     */
    protected function isBanned(string $fingerprint): bool
    {
        $key = self::BAN_KEY_PREFIX . $fingerprint;
        return $this->dataStore->getValue($key) !== null;
    }

    /**
     * Ban a fingerprint for the configured duration.
     */
    protected function banFingerprint(string $fingerprint): void
    {
        $key = self::BAN_KEY_PREFIX . $fingerprint;
        $duration = Config::get(self::CONFIG_KEY_BAN_DURATION, 3600);
        $this->dataStore->setValue($key, now()->timestamp, $duration);
    }

    /**
     * Log when a request is blocked.
     */
    protected function logBlock(Request $request, string $tracking, float $score, float $threshold): void
    {
        Log::warning('Citadel: Request blocked due to suspicious activity', [
            'tracking_id' => $tracking,
            'score' => $score,
            'threshold' => $threshold,
            'ip' => $request->ip(),
            'url' => $request->fullUrl(),
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
     * Generate a response when blocking a request.
     */
    protected function blockResponse(Request $request): mixed
    {
        $responseType = Config::get(self::CONFIG_KEY_RESPONSE_TYPE, 'abort');

        return match ($responseType) {
            'abort' => abort(
                Config::get(self::CONFIG_KEY_RESPONSE_CODE, 403),
                Config::get(self::CONFIG_KEY_RESPONSE_MESSAGE, 'Forbidden')
            ),
            'view' => response()->view(
                Config::get(self::CONFIG_KEY_RESPONSE_VIEW, 'errors.403'),
                ['message' => Config::get(self::CONFIG_KEY_RESPONSE_MESSAGE, 'Forbidden')],
                Config::get(self::CONFIG_KEY_RESPONSE_CODE, 403)
            ),
            'json' => response()->json(
                ['error' => Config::get(self::CONFIG_KEY_RESPONSE_MESSAGE, 'Forbidden')],
                Config::get(self::CONFIG_KEY_RESPONSE_CODE, 403)
            ),
            default => abort(403, 'Forbidden'),
        };
    }
}
