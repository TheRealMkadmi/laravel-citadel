<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use TheRealMkadmi\Citadel\Drivers\DataStore;

class BurstinessAnalyzer implements IRequestAnalyzer
{
    /**
     * @var DataStore
     */
    protected DataStore $dataStore;

    /**
     * Constructor.
     *
     * @param DataStore $dataStore The data store responsible for persistence.
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Analyze the incoming order request for burstiness.
     *
     * @param Request $request
     * @return float
     */
    public function analyze(Request $request): float
    {
        $fingerprint = $request->getFingerprint();
        $score = 0;
        
        // Use Redis for implementing sliding window rate limiting
        $key = "fw:{$fingerprint}:requests";
        $now = (int) round(microtime(true) * 1000); // Current time in milliseconds
        $windowSize = config('citadel.burstiness.window_size', 60000); // Default: 60 seconds in ms
        $minInterval = config('citadel.burstiness.min_interval', 5000); // Default: 5 seconds in ms
        
        // Calculate cutoff time for the sliding window
        $cutoff = $now - $windowSize;
        
        // Pipeline Redis commands for atomic execution
        $results = Redis::pipeline(function($pipe) use ($key, $cutoff, $now, $windowSize) {
            // Remove timestamps older than the window from the sorted set
            $pipe->zremrangebyscore($key, '-inf', $cutoff);
            
            // Add the current timestamp to the sorted set
            $pipe->zadd($key, $now, $now);
            
            // Set expiry for the key (window size + buffer)
            $pipe->expire($key, (int)($windowSize / 1000 * 2)); // 2x window size in seconds
            
            // Count the number of requests in the current window
            $pipe->zcard($key);
            
            // Get the second-to-last timestamp (for burst detection)
            $pipe->zrange($key, -2, -2);
        });
        
        // Extract results
        $requestCount = $results[3] ?? 1; // Default to 1 if no count returned
        $lastTimeArray = $results[4] ?? []; // Previous timestamp if exists
        
        // Calculate frequency score: penalize for exceeding maximum requests
        $maxRequestsPerWindow = config('citadel.burstiness.max_requests_per_window', 5);
        if ($requestCount > $maxRequestsPerWindow) {
            // Calculate excess and apply scoring
            $excess = $requestCount - $maxRequestsPerWindow;
            $frequencyScore = $excess * config('citadel.burstiness.excess_request_score', 10);
            
            // Cap the score at maximum value if extremely high frequency
            $score += min($frequencyScore, config('citadel.burstiness.max_frequency_score', 100));
        }
        
        // Burst detection: Check if time since last request is less than minimum interval
        $burstDetected = false;
        if (!empty($lastTimeArray)) {
            $lastTime = (int)$lastTimeArray[0];
            $timeSinceLastRequest = $now - $lastTime;
            
            if ($timeSinceLastRequest < $minInterval) {
                $burstDetected = true;
                $score += config('citadel.burstiness.burst_penalty_score', 20);
            }
        }
        
        return (float)$score;
    }
}