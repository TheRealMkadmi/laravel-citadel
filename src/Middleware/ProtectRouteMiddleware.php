<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;

class ProtectRouteMiddleware
{
    /**
     * Collection of request analyzers
     *
     * @var array<IRequestAnalyzer>
     */
    protected array $analyzers = [];

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
     */
    public function __construct(array $analyzers = [])
    {
        $this->analyzers = $analyzers;
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
        
        // Process each analyzer and collect scores
        foreach ($this->analyzers as $analyzer) {
            $analyzerName = get_class($analyzer);
            $shortName = class_basename($analyzer);
            
            try {
                // Run the analyzer
                $score = $analyzer->analyze($request);
                $totalScore += $score;
                $scoreBreakdown[$shortName] = $score;
                
                // Log each analyzer's score
                Log::debug("Citadel: {$shortName} score", [
                    'fingerprint' => $fingerprint,
                    'analyzer' => $shortName,
                    'score' => $score,
                    'url' => $request->fullUrl(),
                ]);
                
                // Early return if we're already above the threshold
                if ($totalScore >= $this->threshold) {
                    Log::warning("Citadel: Request blocked due to high suspect score", [
                        'fingerprint' => $fingerprint,
                        'total_score' => $totalScore,
                        'threshold' => $this->threshold,
                        'breakdown' => $scoreBreakdown,
                        'url' => $request->fullUrl(),
                        'terminated_by' => $shortName,
                    ]);
                    
                    return response()->json([
                        'message' => 'Request blocked due to suspicious activity',
                    ], 403);
                }
            } catch (\Throwable $e) {
                // Log errors but don't block requests due to analyzer failures
                Log::error("Citadel: Analyzer error in {$shortName}", [
                    'fingerprint' => $fingerprint,
                    'analyzer' => $shortName,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]);
            }
        }
        
        // Log the final score
        Log::debug("Citadel: Final score for request", [
            'fingerprint' => $fingerprint,
            'total_score' => $totalScore,
            'threshold' => $this->threshold,
            'breakdown' => $scoreBreakdown,
            'url' => $request->fullUrl(),
            'passed' => true,
        ]);
        
        // Allow the request to proceed if the score is below the threshold
        $response = $next($request);
        
        // Update fail counters if the response indicates an error
        if ($response->getStatusCode() >= 400) {
            // Implementation for tracking failures could be added here
            // This would integrate with the failure tracking described in the design doc
        }
        
        return $response;
    }
}
