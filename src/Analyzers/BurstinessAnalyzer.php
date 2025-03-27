<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use TheRealMkadmi\Citadel\Contracts\DataStore;

class BurstinessAnalyzer implements IRequestAnalyzer
{
    /**
     * The key prefix for fingerprint request data.
     */
    private const KEY_PREFIX = 'fw';

    /**
     * The DataStore instance.
     */
    protected DataStore $dataStore;

    /**
     * Constructor.
     *
     * @param  DataStore  $dataStore  The data store implementation.
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
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
        $fingerprint = $request->getFingerprint();
        $score = 0;

        // Get configuration values
        $windowSize = Config::get('citadel.burstiness.window_size', 60000);
        $minInterval = Config::get('citadel.burstiness.min_interval', 5000);
        $maxRequestsPerWindow = Config::get('citadel.burstiness.max_requests_per_window', 5);
        $excessRequestScore = Config::get('citadel.burstiness.excess_request_score', 10);
        $burstPenaltyScore = Config::get('citadel.burstiness.burst_penalty_score', 20);
        $maxFrequencyScore = Config::get('citadel.burstiness.max_frequency_score', 100);

        // Current time in milliseconds
        $now = $this->getCurrentTimeInMilliseconds();

        // Generate keys for data storage
        $keySuffix = $this->getKeySuffix($fingerprint);
        $requestsKey = $this->generateKeyName($keySuffix, 'requests');
        $patternKey = $this->generateKeyName($keySuffix, 'pattern');
        $historyKey = $this->generateKeyName($keySuffix, 'history');

        // Calculate cutoff time for the sliding window
        $cutoff = $now - $windowSize;

        // TTL in seconds (window size + buffer)
        $keyTTL = $this->calculateTTL($windowSize);

        // Execute multiple operations atomically using the pipeline
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

        // Extract results
        $requestCount = $results[3] ?? 1; // Default to 1 if no count returned
        $recentTimestamps = $results[4] ?? []; // Last 5 timestamps if they exist

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
        // Check for rapid consecutive requests (bursts)
        $burstDetected = $this->detectBurst($recentTimestamps, $minInterval);
        if ($burstDetected) {
            // Apply penalty for burst detection
            $score += $burstPenaltyScore;
        }

        // ===== PATTERN ANALYSIS =====
        // Check for regularity in request timing that might indicate automation
        $minSamplesForPatternDetection = Config::get('citadel.burstiness.min_samples_for_pattern', 3);
        if (count($recentTimestamps) >= $minSamplesForPatternDetection) {
            $patternScore = $this->analyzeRequestPatterns($recentTimestamps, $patternKey, $keyTTL);
            $score += $patternScore;
        }

        // ===== HISTORICAL BEHAVIOR ANALYSIS =====
        // Apply additional penalties for repeat offenders
        $historyScore = $this->getHistoricalScore($historyKey);
        $score += $historyScore;

        return (float) $score;
    }

    /**
     * Detect bursts (requests coming too rapidly in succession).
     *
     * @param  array  $timestamps  Recent request timestamps
     * @param  int  $minInterval  Minimum acceptable interval between requests
     * @return bool Whether a burst was detected
     */
    protected function detectBurst(array $timestamps, int $minInterval): bool
    {
        // Need at least 2 timestamps to detect a burst
        if (count($timestamps) < 2) {
            return false;
        }

        // Convert string timestamps to integers if needed
        $numericTimestamps = array_map('intval', $timestamps);

        // Sort timestamps in ascending order
        sort($numericTimestamps);

        // Check for bursts in the entire sequence
        for ($i = 1; $i < count($numericTimestamps); $i++) {
            $interval = $numericTimestamps[$i] - $numericTimestamps[$i - 1];
            if ($interval < $minInterval) {
                return true;
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
        $intervals = [];
        for ($i = 1; $i < count($numericTimestamps); $i++) {
            $intervals[] = $numericTimestamps[$i] - $numericTimestamps[$i - 1];
        }

        // Check for regularity in intervals (standard deviation approach)
        if (count($intervals) >= 2) {
            // Calculate mean interval
            $meanInterval = array_sum($intervals) / count($intervals);

            // Calculate variance
            $variance = 0;
            foreach ($intervals as $interval) {
                $variance += pow($interval - $meanInterval, 2);
            }
            $variance /= count($intervals);

            // Calculate coefficient of variation (CV)
            // CV = (standard deviation / mean) - lower value indicates more regularity
            $stdDev = sqrt($variance);
            $cv = ($meanInterval > 0) ? $stdDev / $meanInterval : 0;

            // Store pattern analysis data
            $patternData = $this->dataStore->getValue($patternKey, [
                'cv_history' => [],
                'mean_interval' => 0,
                'detection_count' => 0,
            ]);

            // Update pattern history
            $patternData['cv_history'][] = $cv;
            $maxHistorySize = Config::get('citadel.burstiness.pattern_history_size', 5);
            if (count($patternData['cv_history']) > $maxHistorySize) {
                array_shift($patternData['cv_history']);
            }
            $patternData['mean_interval'] = $meanInterval;

            // Detect if CV is consistently low (suggests regular pattern)
            $avgCV = array_sum($patternData['cv_history']) / count($patternData['cv_history']);

            // Score based on coefficient of variation thresholds
            $patternScore = 0;
            $veryRegularThreshold = Config::get('citadel.burstiness.very_regular_threshold', 0.1);
            $somewhatRegularThreshold = Config::get('citadel.burstiness.somewhat_regular_threshold', 0.25);
            $veryRegularScore = Config::get('citadel.burstiness.very_regular_score', 30);
            $somewhatRegularScore = Config::get('citadel.burstiness.somewhat_regular_score', 15);
            $patternMultiplier = Config::get('citadel.burstiness.pattern_multiplier', 5);
            $maxPatternScore = Config::get('citadel.burstiness.max_pattern_score', 20);

            if ($avgCV < $veryRegularThreshold) {
                // Very regular pattern - likely a bot
                $patternData['detection_count']++;
                $patternScore = $veryRegularScore;
            } elseif ($avgCV < $somewhatRegularThreshold) {
                // Somewhat regular pattern - suspicious
                $patternData['detection_count']++;
                $patternScore = $somewhatRegularScore;
            } else {
                // Irregular pattern - likely human
                $patternData['detection_count'] = max(0, $patternData['detection_count'] - 1);
            }

            // Additional score for repeated pattern detections
            $patternScore += min($maxPatternScore, $patternData['detection_count'] * $patternMultiplier);

            // Save updated pattern data
            $this->dataStore->setValue($patternKey, $patternData, $ttl);

            return (float) $patternScore;
        }

        return 0;
    }

    /**
     * Track history of excessive requests for repeat offender detection.
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

        // Update history data
        $history['last_violation'] = $timestamp;
        $history['violation_count']++;
        $history['max_excess'] = max($history['max_excess'], $excess);
        $history['total_excess'] += $excess;

        // Store with a longer TTL to track persistent offenders
        $historyMultiplier = Config::get('citadel.burstiness.history_ttl_multiplier', 6);
        $this->dataStore->setValue($historyKey, $history, $ttl * $historyMultiplier);
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
        $history = $this->dataStore->getValue($historyKey, null);

        // No history found
        if (! $history) {
            return 0;
        }

        $historyScore = 0;

        // Add penalty based on violation frequency
        $minViolationsForPenalty = Config::get('citadel.burstiness.min_violations_for_penalty', 1);
        $maxViolationScore = Config::get('citadel.burstiness.max_violation_score', 50);

        if ($history['violation_count'] > $minViolationsForPenalty) {
            // Progressive penalty for repeat offenders
            $historyScore += min($maxViolationScore, pow($history['violation_count'], 1.5));
        }

        // Add penalty for severe violations (high excess)
        $severeExcessThreshold = Config::get('citadel.burstiness.severe_excess_threshold', 10);
        $maxExcessScore = Config::get('citadel.burstiness.max_excess_score', 30);
        $excessMultiplier = Config::get('citadel.burstiness.excess_multiplier', 2);

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
        $bufferMultiplier = Config::get('citadel.burstiness.ttl_buffer_multiplier', 2);

        return (int) ($windowSize / 1000 * $bufferMultiplier);
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

    /**
     * Get the key suffix from the fingerprint.
     *
     * @param  string  $fingerprint  The user fingerprint
     * @return string The key suffix
     */
    protected function getKeySuffix(string $fingerprint): string
    {
        return $fingerprint;
    }
}
