<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class BurstinessAnalyzer extends AbstractAnalyzer
{
    /**
     * The key prefix for fingerprint request data.
     */
    private const KEY_PREFIX = 'burst';

    /**
     * Indicates if this analyzer scans payload content.
     */
    protected bool $scansPayload = false;

    /**
     * This analyzer doesn't make external requests.
     */
    protected bool $active = false;
    
    /**
     * Local cache for config values to avoid repeated lookups
     */
    protected array $configCache = [];

    /**
     * Constructor.
     *
     * @param  DataStore  $dataStore  The data store implementation.
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);
        $this->enabled = config('citadel.burstiness.enable_burstiness_analyzer', true);
        $this->cacheTtl = config(CitadelConfig::KEY_CACHE.'.burst_analysis_ttl', 3600);
        
        // Pre-load frequently used configuration values
        $this->loadConfigValues();
    }
    
    /**
     * Load commonly used configuration values to reduce lookups
     */
    protected function loadConfigValues(): void
    {
        $this->configCache = [
            'windowSize' => (int)Config::get(CitadelConfig::KEY_BURSTINESS.'.window_size', 60000),
            'minInterval' => (int)Config::get(CitadelConfig::KEY_BURSTINESS.'.min_interval', 5000),
            'maxRequestsPerWindow' => (int)Config::get(CitadelConfig::KEY_BURSTINESS.'.max_requests_per_window', 5),
            'excessRequestScore' => (float)Config::get(CitadelConfig::KEY_BURSTINESS.'.excess_request_score', 10),
            'burstPenaltyScore' => (float)Config::get(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 20),
            'maxFrequencyScore' => (float)Config::get(CitadelConfig::KEY_BURSTINESS.'.max_frequency_score', 100),
            'veryRegularThreshold' => (float)Config::get('citadel.burstiness.very_regular_threshold', 0.1),
            'somewhatRegularThreshold' => (float)Config::get('citadel.burstiness.somewhat_regular_threshold', 0.25),
            'veryRegularScore' => (float)Config::get('citadel.burstiness.very_regular_score', 30),
            'somewhatRegularScore' => (float)Config::get('citadel.burstiness.somewhat_regular_score', 15),
            'patternMultiplier' => (float)Config::get('citadel.burstiness.pattern_multiplier', 5),
            'maxPatternScore' => (float)Config::get('citadel.burstiness.max_pattern_score', 20),
            'minSamplesForPatternDetection' => (int)Config::get('citadel.burstiness.min_samples_for_pattern', 3),
            'patternHistorySize' => (int)Config::get('citadel.burstiness.pattern_history_size', 5),
            'historyTtlMultiplier' => (int)Config::get('citadel.burstiness.history_ttl_multiplier', 6),
            'minViolationsForPenalty' => (int)Config::get('citadel.burstiness.min_violations_for_penalty', 1),
            'maxViolationScore' => (float)Config::get('citadel.burstiness.max_violation_score', 50),
            'severeExcessThreshold' => (int)Config::get('citadel.burstiness.severe_excess_threshold', 10),
            'maxExcessScore' => (float)Config::get('citadel.burstiness.max_excess_score', 30),
            'excessMultiplier' => (float)Config::get('citadel.burstiness.excess_multiplier', 2),
            'ttlBufferMultiplier' => (int)Config::get('citadel.burstiness.ttl_buffer_multiplier', 2),
        ];
    }

    /**
     * Analyze the incoming request for burstiness and suspicious patterns.
     *
     * This method implements advanced rate limiting and pattern detection:
     * 1. Sliding window rate limiting
     * 2. Burst detection (minimum time between requests)
     * 3. Time-based pattern analysis (detects regularity that suggests automation)
     * 4. Adaptive scoring based on historical behavior
     *
     * @return float Score indicating how suspicious the request pattern is
     */
    public function analyze(Request $request): float
    {
        if (!$this->enabled) {
            return 0.0;
        }

        $fingerprint = $request->getFingerprint();
        if (empty($fingerprint)) {
            return 0.0;
        }
        
        // Generate a cache key for this fingerprint's analysis
        $cacheKey = "burstiness:{$fingerprint}";
        
        // Check if we have a cached score to avoid redundant calculations
        $cachedScore = $this->dataStore->getValue($cacheKey);
        if ($cachedScore !== null) {
            return (float) $cachedScore;
        }

        $score = 0;

        // Get configuration values
        $windowSize = $this->configCache['windowSize'];
        $minInterval = $this->configCache['minInterval'];
        $maxRequestsPerWindow = $this->configCache['maxRequestsPerWindow'];
        $excessRequestScore = $this->configCache['excessRequestScore'];
        $burstPenaltyScore = $this->configCache['burstPenaltyScore'];
        $maxFrequencyScore = $this->configCache['maxFrequencyScore'];

        // Current time in milliseconds
        $now = $this->getCurrentTimeInMilliseconds();

        // Generate keys for data storage using short, efficient format
        $keySuffix = Str::substr(md5($fingerprint), 0, 12); // Use shorter fingerprint hash
        $requestsKey = $this->generateKeyName($keySuffix, 'req'); // Shortened key names
        $patternKey = $this->generateKeyName($keySuffix, 'pat');
        $historyKey = $this->generateKeyName($keySuffix, 'hist');

        // Calculate cutoff time for the sliding window
        $cutoff = $now - $windowSize;

        // TTL in seconds (window size + buffer)
        $keyTTL = $this->calculateTTL($windowSize);

        // Execute multiple operations atomically using the pipeline for better performance
        $results = $this->dataStore->pipeline(function ($pipe) use ($requestsKey, $cutoff, $now, $keyTTL) {
            // Remove timestamps older than the window from the sorted set
            $pipe->zremrangebyscore($requestsKey, '-inf', $cutoff);

            // Add the current timestamp to the sorted set
            $pipe->zadd($requestsKey, $now, $now);

            // Set expiry for the key
            $pipe->expire($requestsKey, $keyTTL);

            // Count the number of requests in the current window
            $pipe->zcard($requestsKey);

            // Get the most recent timestamps for pattern analysis
            // We use -5 to get the last 5 entries (including current one)
            $pipe->zrange($requestsKey, -5, -1);
        });

        // Extract results from pipeline with default values if missing
        $requestCount = $results[3] ?? 1; // Default to 1 if no count returned
        $recentTimestamps = $results[4] ?? []; // Last timestamps if they exist

        // ===== FREQUENCY ANALYSIS =====
        // Calculate frequency score: penalize for exceeding maximum requests
        if ($requestCount > $maxRequestsPerWindow) {
            // Calculate excess and apply scoring with progressive penalty
            $excess = $requestCount - $maxRequestsPerWindow;

            // Apply quadratic scaling for repeated offenses to heavily penalize aggressive attackers
            // This makes the penalty grow much faster than linear scaling
            $frequencyScore = $excessRequestScore * pow($excess, 1.5);

            // Cap the score at maximum value
            $score += min($frequencyScore, $maxFrequencyScore);

            // Store historical data for this fingerprint to track repeat offenders
            $this->trackExcessiveRequestHistory($historyKey, $now, $excess, $keyTTL);
        }

        // ===== BURST DETECTION =====
        // Only check for bursts if there are enough timestamps and we haven't already maxed out the score
        if (count($recentTimestamps) >= 3 && $score < $maxFrequencyScore) {
            $burstDetected = $this->detectBurst($recentTimestamps, $minInterval);
            if ($burstDetected) {
                // Apply penalty for burst detection
                $score += $burstPenaltyScore;
            }
            
            // ===== PATTERN ANALYSIS =====
            // Check for regularity in request timing that might indicate automation
            if (count($recentTimestamps) >= $this->configCache['minSamplesForPatternDetection']) {
                $patternScore = $this->analyzeRequestPatterns($recentTimestamps, $patternKey, $keyTTL);
                $score += $patternScore;
            }
        }

        // ===== HISTORICAL BEHAVIOR ANALYSIS =====
        // Apply additional penalties for repeat offenders
        $historyScore = $this->getHistoricalScore($historyKey);
        $score += $historyScore;
        
        // Cache the analysis result to avoid recalculating too frequently
        // Use a short TTL since bursts detection is time-sensitive
        $shortCacheTtl = min(60, $this->cacheTtl); // Maximum 1 minute or shorter
        $this->dataStore->setValue($cacheKey, $score, $shortCacheTtl);

        return (float) $score;
    }

    /**
     * Detect if the request timing shows a burst pattern.
     */
    protected function detectBurst(array $timestamps, int $minInterval): bool
    {
        // Need at least 3 timestamps to detect a burst
        if (count($timestamps) < 3) {
            return false;
        }
        
        // Convert string timestamps to integers and sort
        $numericTimestamps = array_map('intval', $timestamps);
        sort($numericTimestamps);
        
        // Calculate intervals between consecutive requests and check if any are below threshold
        // Using a more efficient direct approach instead of collections
        $burstCount = 0;
        for ($i = 1; $i < count($numericTimestamps); $i++) {
            if (($numericTimestamps[$i] - $numericTimestamps[$i-1]) < $minInterval) {
                $burstCount++;
                if ($burstCount >= 2) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Analyze patterns in request timestamps to detect bot-like behavior.
     *
     * This detects regular intervals which suggest automated requests
     * rather than human interactions which tend to be more random.
     *
     * @param  array  $timestamps  Recent request timestamps
     * @param  string  $patternKey  Key for storing pattern analysis data
     * @param  int  $ttl  TTL for the pattern data
     * @return float Score based on detected patterns
     */
    protected function analyzeRequestPatterns(array $timestamps, string $patternKey, int $ttl): float
    {
        // Need at least 3 timestamps to detect a pattern
        if (count($timestamps) < 3) {
            return 0;
        }

        // Convert string timestamps to integers and sort
        $numericTimestamps = array_map('intval', $timestamps);
        sort($numericTimestamps);

        // Calculate intervals between consecutive requests
        // Pre-allocate the array size for better performance
        $intervals = [];
        $count = count($numericTimestamps);
        for ($i = 1; $i < $count; $i++) {
            $intervals[] = $numericTimestamps[$i] - $numericTimestamps[$i - 1];
        }

        // Check for regularity in intervals (standard deviation approach)
        $intervalCount = count($intervals);
        if ($intervalCount >= 2) {
            // Calculate mean interval - use array_sum directly for performance
            $meanInterval = array_sum($intervals) / $intervalCount;

            // Calculate variance with optimized approach
            $variance = 0;
            foreach ($intervals as $interval) {
                $variance += ($interval - $meanInterval) ** 2;
            }
            $variance /= $intervalCount;

            // Calculate coefficient of variation (CV)
            // CV = (standard deviation / mean) - lower value indicates more regularity
            $stdDev = sqrt($variance);
            $cv = ($meanInterval > 0) ? $stdDev / $meanInterval : 0;

            // Store pattern analysis data
            $patternData = $this->dataStore->getValue($patternKey, [
                'cv_history' => [],
                'mean_interval' => 0,
                'detection_count' => 0,
                'last_updated' => 0,
            ]);
            
            // Only update if it's a new request (checking timestamp can help avoid redundant processing)
            $currentTime = time();
            if ($currentTime > ($patternData['last_updated'] + 1)) {
                // Update pattern history
                $patternData['cv_history'][] = $cv;
                $maxHistorySize = $this->configCache['patternHistorySize'];
                if (count($patternData['cv_history']) > $maxHistorySize) {
                    array_shift($patternData['cv_history']);
                }
                $patternData['mean_interval'] = $meanInterval;
                $patternData['last_updated'] = $currentTime;

                // Detect if CV is consistently low (suggests regular pattern)
                // Reuse variable names for memory efficiency
                $cvCount = count($patternData['cv_history']);
                $avgCV = array_sum($patternData['cv_history']) / $cvCount;

                // Score based on coefficient of variation thresholds
                $patternScore = 0;
                
                // Use cached config values for better performance
                if ($avgCV < $this->configCache['veryRegularThreshold']) {
                    // Very regular pattern - likely a bot
                    $patternData['detection_count']++;
                    $patternScore = $this->configCache['veryRegularScore'];
                } elseif ($avgCV < $this->configCache['somewhatRegularThreshold']) {
                    // Somewhat regular pattern - suspicious
                    $patternData['detection_count']++;
                    $patternScore = $this->configCache['somewhatRegularScore'];
                } else {
                    // Irregular pattern - likely human
                    $patternData['detection_count'] = max(0, $patternData['detection_count'] - 1);
                }

                // Additional score for repeated pattern detections
                $patternScore += min(
                    $this->configCache['maxPatternScore'], 
                    $patternData['detection_count'] * $this->configCache['patternMultiplier']
                );

                // Save updated pattern data
                $this->dataStore->setValue($patternKey, $patternData, $ttl);

                return (float) $patternScore;
            }
            
            // Calculate pattern score based on existing data
            $avgCV = array_sum($patternData['cv_history']) / count($patternData['cv_history']);
            
            if ($avgCV < $this->configCache['veryRegularThreshold']) {
                return $this->configCache['veryRegularScore'] + 
                       min($this->configCache['maxPatternScore'], 
                           $patternData['detection_count'] * $this->configCache['patternMultiplier']);
            } elseif ($avgCV < $this->configCache['somewhatRegularThreshold']) {
                return $this->configCache['somewhatRegularScore'] + 
                       min($this->configCache['maxPatternScore'], 
                           $patternData['detection_count'] * $this->configCache['patternMultiplier']);
            }
        }

        return 0;
    }

    /**
     * Track history of excessive requests for repeat offender detection with optimized storage.
     *
     * @param  string  $historyKey  Key for storing historical data
     * @param  int  $timestamp  Current timestamp
     * @param  int  $excess  Number of excess requests
     * @param  int  $ttl  TTL for the history data
     */
    protected function trackExcessiveRequestHistory(string $historyKey, int $timestamp, int $excess, int $ttl): void
    {
        // Get existing history data or initialize a new record
        $history = $this->dataStore->getValue($historyKey, [
            'first_violation' => $timestamp,
            'last_violation' => $timestamp,
            'violation_count' => 0,
            'max_excess' => 0,
            'total_excess' => 0,
        ]);

        // Update history data if this is truly a new violation (not the same second)
        if ($timestamp > $history['last_violation'] + 1000) { 
            // Update history data
            $history['last_violation'] = $timestamp;
            $history['violation_count']++;
            $history['max_excess'] = max($history['max_excess'], $excess);
            $history['total_excess'] += $excess;

            // Store with a longer TTL to track persistent offenders
            $this->dataStore->setValue(
                $historyKey, 
                $history, 
                $ttl * $this->configCache['historyTtlMultiplier']
            );
        }
    }

    /**
     * Calculate additional score based on historical behavior.
     *
     * This implements a memory mechanism to penalize repeat offenders
     * more severely than first-time violators.
     *
     * @param  string  $historyKey  Key for stored historical data
     * @return float Additional score based on history
     */
    protected function getHistoricalScore(string $historyKey): float
    {
        $history = $this->dataStore->getValue($historyKey);

        // No history found
        if (!$history) {
            return 0;
        }

        $historyScore = 0;

        // Add penalty based on violation frequency
        $minViolationsForPenalty = $this->configCache['minViolationsForPenalty'];
        $maxViolationScore = $this->configCache['maxViolationScore'];

        if ($history['violation_count'] > $minViolationsForPenalty) {
            // Progressive penalty for repeat offenders using cached config
            $historyScore += min($maxViolationScore, pow($history['violation_count'], 1.5));
        }

        // Add penalty for severe violations (high excess) using cached config
        $severeExcessThreshold = $this->configCache['severeExcessThreshold'];
        $maxExcessScore = $this->configCache['maxExcessScore'];
        $excessMultiplier = $this->configCache['excessMultiplier'];

        if ($history['max_excess'] > $severeExcessThreshold) {
            $historyScore += min($maxExcessScore, $history['max_excess'] * $excessMultiplier);
        }

        return (float) $historyScore;
    }

    /**
     * Get the current time in milliseconds.
     *
     * @return int Current timestamp in milliseconds
     */
    protected function getCurrentTimeInMilliseconds(): int
    {
        return (int) round(microtime(true) * 1000);
    }

    /**
     * Calculate the TTL in seconds based on window size in milliseconds.
     *
     * @param  int  $windowSize  The window size in milliseconds
     * @return int TTL in seconds
     */
    protected function calculateTTL(int $windowSize): int
    {
        // Use cached buffer multiplier for performance
        return (int) ($windowSize / 1000 * $this->configCache['ttlBufferMultiplier']);
    }

    /**
     * Generate a key name with the appropriate format.
     *
     * @param  string  $suffix  The key suffix (e.g. fingerprint)
     * @param  string  $type  The key type (e.g. 'requests', 'pattern')
     * @return string The formatted key name
     */
    protected function generateKeyName(string $suffix, string $type): string
    {
        return sprintf('%s:%s:%s', self::KEY_PREFIX, $suffix, $type);
    }
}
