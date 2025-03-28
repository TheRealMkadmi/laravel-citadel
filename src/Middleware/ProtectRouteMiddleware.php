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
     */
    public function handle(Request $request, Closure $next): mixed
    {
        // Skip all checks if middleware is disabled or global protection is disabled
        if (! Config::get(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true) ||
            ! Config::get(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true)) {
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

        // Get applicable analyzers based on request characteristics
        $applicableAnalyzers = $this->getApplicableAnalyzers($request);

        // Skip if no analyzers are applicable
        if (empty($applicableAnalyzers)) {
            return $next($request);
        }

        // Run applicable analyzers and get results
        $analysisResult = $this->runAnalyzers($request, $applicableAnalyzers);
        $scores = collect($analysisResult['scores']);
        $totalScore = $scores->sum();

        // Check if score is above threshold - block if yes
        $thresholdScore = Config::get(CitadelConfig::KEY_MIDDLEWARE_THRESHOLD_SCORE, 100);
        if ($totalScore > $thresholdScore) {
            $this->logBlocking($request, $scores->toArray(), $totalScore, $thresholdScore);

            // Ban if enabled
            if (Config::get(CitadelConfig::KEY_MIDDLEWARE_BAN_ENABLED, false)) {
                $this->banFingerprint($fingerprint);
            }

            return $this->blockRequest($request);
        }

        // Log scores for suspicious requests (even if below threshold)
        $warningThreshold = Config::get(CitadelConfig::KEY_MIDDLEWARE_WARNING_THRESHOLD, 80);
        if ($totalScore > $warningThreshold) {
            $this->logWarning($request, $scores->toArray(), $totalScore);
        }

        // Request passed all checks, proceed
        return $next($request);
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

                // Get cache key for analyzer results
                $cacheKey = $this->getCacheKey($request->getFingerprint(), $analyzerName);

                // Try to get cached result
                $cachedScore = $this->dataStore->getValue($cacheKey);
                $score = $cachedScore !== null ? (float) $cachedScore : $analyzer->analyze($request);

                // Cache the score if not already cached
                if ($cachedScore === null) {
                    // Get configurable cache TTL for analyzer results, default to 1 hour
                    $ttl = Config::get(CitadelConfig::KEY_MIDDLEWARE_CACHE_TTL, 3600);
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
            'totalScore' => $scores->sum(),
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
        return match($responseType) {
            ResponseType::JSON => response()->json(['error' => $responseMessage], $responseCode),
            ResponseType::VIEW => $responseView ? response()->view($responseView, ['message' => $responseMessage], $responseCode)
                                               : response($responseMessage, $responseCode),
            default => response($responseMessage, $responseCode),
        };
    }
}
