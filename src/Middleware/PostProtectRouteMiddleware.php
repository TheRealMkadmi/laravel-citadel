<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class PostProtectRouteMiddleware
{
    /**
     * Configuration keys.
     */
    private const CONFIG_KEY_PASSIVE_ENABLED = 'citadel.middleware.passive_enabled';

    private const CONFIG_KEY_THRESHOLD_SCORE = 'citadel.middleware.threshold_score';

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
     * Unlike ProtectRouteMiddleware, this never blocks requests - it only monitors and logs.
     */
    public function handle(Request $request, Closure $next)
    {
        // Allow the request to proceed first
        $response = $next($request);

        // If no analyzers are registered or middleware is disabled, just return
        if (empty($this->analyzers) || ! Config::get(self::CONFIG_KEY_PASSIVE_ENABLED, true)) {
            return $response;
        }

        // Get the user's fingerprint
        $tracking = $request->getFingerprint();
        $scores = collect();

        // Run all registered analyzers and collect their scores
        foreach ($this->analyzers as $analyzer) {
            try {
                $analyzerName = class_basename($analyzer);
                $score = $analyzer->analyze($request);

                // Store individual analyzer scores
                $scores->put($analyzerName, $score);
            } catch (\Exception $e) {
                // Log the error but don't block the request
                Log::error('Citadel passive analyzer error: {message}', [
                    'message' => $e->getMessage(),
                    'analyzer' => class_basename($analyzer),
                    'tracking_id' => $tracking,
                    'exception' => $e,
                ]);
            }
        }

        // Log suspicious activity but never block
        $thresholdScore = Config::get(self::CONFIG_KEY_THRESHOLD_SCORE, 100);
        $totalScore = $scores->sum();

        if ($totalScore > $thresholdScore) {
            Log::warning('Citadel: Passive detection of suspicious activity', [
                'tracking_id' => $tracking,
                'scores' => $scores->toArray(),
                'total_score' => $totalScore,
                'threshold' => $thresholdScore,
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'user_agent' => $request->userAgent(),
            ]);
        }

        return $response;
    }
}
