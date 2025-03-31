<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\AnalyzerType;

class BurstinessAnalyzer extends AbstractAnalyzer
{
    /**
     * Constants for key prefixes and types
     */
    private const KEY_PREFIX = 'burst';

    private const CACHE_PREFIX = 'burstiness';

    private const TYPE_REQUEST = 'req';

    private const TYPE_PATTERN = 'pat';

    private const TYPE_HISTORY = 'hist';

    private const TYPE_BURST = 'burst';

    /**
     * Request pattern types
     */
    private const PATTERN_NORMAL = 'normal';

    private const PATTERN_REGULAR = 'regular';

    private const PATTERN_BURST = 'burst';

    /**
     * Violation types
     */
    private const VIOLATION_TYPE_EXCESS = 'excess';

    private const VIOLATION_TYPE_BURST = 'burst';

    private const VIOLATION_TYPE_REGULAR = 'regular';

    /**
     * Scoring constants
     */
    private const BASE_LOGARITHM = 2.0;

    private const SEVERE_EXCESS_DIVISOR = 5.0;

    private const GROWTH_FACTOR_MULTIPLIER = 2.0;

    private const GROWTH_FACTOR_BASE = 1.0;

    private const UNIQUE_PATTERN_SCORE_MODIFIER = 0.1;

    private const INTERVAL_DIVISOR = 10;

    private const HISTORY_MULTIPLIER_BASE = 1.5;

    private const HISTORY_PENALTY_INCREMENT = 0.3;

    private const REPEAT_VIOLATION_MULTIPLIER = 1.2;

    
    /**
     * Whether this takes active action against the request or the client to decide
     */
    protected AnalyzerType $analyzerType = AnalyzerType::PASSIVE;
    
    /**
     * Cache of configuration values
     */
    protected array $configCache = [];

    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);
        $this->enabled = config(CitadelConfig::KEY_BURSTINESS.'.enable_burstiness_analyzer', true);
        $this->cacheTtl = config(CitadelConfig::KEY_CACHE.'.burst_analysis_ttl', 3600);
        $this->loadConfigValues();
    }

    /**
     * Load configuration values into a cache for faster access
     */
    protected function loadConfigValues(): void
    {
        $this->configCache = [
            'windowSize' => (int) config(CitadelConfig::KEY_BURSTINESS.'.window_size', 60000),
            'minInterval' => (int) config(CitadelConfig::KEY_BURSTINESS.'.min_interval', 5000),
            'maxRequestsPerWindow' => (int) config(CitadelConfig::KEY_BURSTINESS.'.max_requests_per_window', 5),
            'extremeRequestThreshold' => (int) config(CitadelConfig::KEY_BURSTINESS.'.extreme_request_threshold', 15),
            'excessRequestScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.excess_request_score', 10),
            'burstPenaltyScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.burst_penalty_score', 20),
            'maxFrequencyScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.max_frequency_score', 100),
            'veryRegularThreshold' => (float) config(CitadelConfig::KEY_BURSTINESS.'.very_regular_threshold', 0.1),
            'somewhatRegularThreshold' => (float) config(CitadelConfig::KEY_BURSTINESS.'.somewhat_regular_threshold', 0.25),
            'veryRegularScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.very_regular_score', 30),
            'somewhatRegularScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.somewhat_regular_score', 15),
            'patternHistorySize' => (int) config(CitadelConfig::KEY_BURSTINESS.'.pattern_history_size', 5),
            'historyTtlMultiplier' => (int) config(CitadelConfig::KEY_BURSTINESS.'.history_ttl_multiplier', 6),
            'minViolationsForPenalty' => (int) config(CitadelConfig::KEY_BURSTINESS.'.min_violations_for_penalty', 1),
            'maxViolationScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.max_violation_score', 50),
            'severeExcessThreshold' => (int) config(CitadelConfig::KEY_BURSTINESS.'.severe_excess_threshold', 10),
            'maxExcessScore' => (float) config(CitadelConfig::KEY_BURSTINESS.'.max_excess_score', 30),
            'excessMultiplier' => (float) config(CitadelConfig::KEY_BURSTINESS.'.excess_multiplier', 2),
            'ttlBufferMultiplier' => (int) config(CitadelConfig::KEY_BURSTINESS.'.ttl_buffer_multiplier', 2),
            'minSamplesForPatternDetection' => (int) config(CitadelConfig::KEY_BURSTINESS.'.min_samples_for_pattern', 3),
        ];
    }

    /**
     * Analyze a request for burstiness patterns
     */
    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            Log::debug('Citadel: BurstinessAnalyzer disabled');

            return 0.0;
        }

        $fingerprint = $request->getFingerprint();
        if (empty($fingerprint)) {
            Log::debug('Citadel: Empty fingerprint in BurstinessAnalyzer');

            return 0.0;
        }

        // Use a distinct cache key for final computed scores to avoid conflicts with raw data
        $cacheKey = self::CACHE_PREFIX.":{$fingerprint}";

        $now = $this->getCurrentTimeInMilliseconds();
        $keySuffix = Str::substr(md5($fingerprint), 0, 12);
        $requestsKey = $this->generateKeyName($keySuffix, self::TYPE_REQUEST);
        $patternKey = $this->generateKeyName($keySuffix, self::TYPE_PATTERN);
        $historyKey = $this->generateKeyName($keySuffix, self::TYPE_HISTORY);

        Log::debug('Citadel: BurstinessAnalyzer analyzing request', [
            'fingerprint' => $fingerprint,
            'keySuffix' => $keySuffix,
            'requestsKey' => $requestsKey,
            'patternKey' => $patternKey,
            'historyKey' => $historyKey,
            'timestamp' => $now,
        ]);

        try {
            // 1. Record timestamp & get history
            $this->dataStore->zAdd($requestsKey, $now, $now);
            $this->dataStore->expire($requestsKey, $this->calculateTTL($this->configCache['windowSize']));
            $this->dataStore->zremrangebyscore($requestsKey, '-inf', $now - $this->configCache['windowSize']);
            $requestCount = $this->dataStore->zCard($requestsKey);
            $recentTimestamps = $this->dataStore->zRange($requestsKey, 0, -1);
            Log::debug('Citadel: Request history details', [
                'requestCount' => $requestCount,
                'windowSize' => $this->configCache['windowSize'],
                'timestampsCount' => count($recentTimestamps),
                'timestamps' => $recentTimestamps,
            ]);

            // --- Scoring Logic ---
            $currentPatternScore = 0.0;
            $violationTrackedThisRequest = false;
            $excessThisRequest = 0;
            $isBurstThisRequest = false;

            // 2. Detect pattern type (prioritizes stored history/stats over simple spacing)
            $patternType = $this->detectPatternType($recentTimestamps, $patternKey);
            Log::debug('Citadel: Initial pattern type detected', ['patternType' => $patternType]);

            // 3. Handle specific pattern types
            if ($patternType === self::PATTERN_REGULAR) {
                // Handle regular pattern score
                $currentPatternScore = $this->configCache['veryRegularScore'];
                if ($requestCount > $this->configCache['maxRequestsPerWindow']) {
                    $excessThisRequest = $requestCount - $this->configCache['maxRequestsPerWindow'];
                    $currentPatternScore += $excessThisRequest * self::UNIQUE_PATTERN_SCORE_MODIFIER;
                    // Track violation for excess within a regular pattern
                    $this->trackViolationHistory($historyKey, $now, $excessThisRequest, $this->configCache['windowSize'], self::VIOLATION_TYPE_EXCESS);
                    $violationTrackedThisRequest = true;
                }
                Log::debug('Citadel: Regular pattern score calculated', ['currentScore' => $currentPatternScore]);

            } else { // Pattern wasn't detected as Regular initially
                // Now, check if it qualifies as Normal (well-spaced)
                if ($requestCount <= $this->configCache['maxRequestsPerWindow'] && $this->isWellSpacedPattern($recentTimestamps)) {
                    $patternType = self::PATTERN_NORMAL; // Override to Normal
                    Log::debug('Citadel: Overridden to Normal (well-spaced) pattern');
                    $currentPatternScore = 0.0;
                } else {
                    // If not Normal or Regular, it must be Burst/Excess
                    $patternType = self::PATTERN_BURST; // Ensure type is set correctly

                    // Calculate excess score component
                    if ($requestCount > $this->configCache['maxRequestsPerWindow']) {
                        $excessThisRequest = $requestCount - $this->configCache['maxRequestsPerWindow'];
                        $baseExcessScore = $this->configCache['excessRequestScore'] * $excessThisRequest;
                        $growthFactor = self::GROWTH_FACTOR_BASE;
                        if ($excessThisRequest > 1) {
                            $growthFactor = self::GROWTH_FACTOR_BASE + (log($excessThisRequest, self::BASE_LOGARITHM) * self::GROWTH_FACTOR_MULTIPLIER);
                        }
                        $progressiveScore = $baseExcessScore * $growthFactor;
                        $severeExcessThreshold = $this->configCache['severeExcessThreshold'];
                        if ($excessThisRequest > $severeExcessThreshold) {
                            $excessMultiplier = $this->configCache['excessMultiplier'];
                            $severityFactor = 1.0 + (($excessThisRequest - $severeExcessThreshold) / self::SEVERE_EXCESS_DIVISOR);
                            $progressiveScore *= $excessMultiplier * $severityFactor;
                        }
                        $excessScore = min($progressiveScore, $this->configCache['maxFrequencyScore']);
                        $currentPatternScore += $excessScore;
                        Log::debug('Citadel: Excess request score calculated', ['currentScore' => $excessScore]);

                        // Track excess violation
                        $this->trackViolationHistory($historyKey, $now, $excessThisRequest, $this->configCache['windowSize'], self::VIOLATION_TYPE_EXCESS);
                        $violationTrackedThisRequest = true;
                    }

                    // Check for burst pattern
                    if (count($recentTimestamps) >= 2) {
                        $isBurstThisRequest = $this->detectBurst($recentTimestamps, $this->configCache['minInterval']);
                        if ($isBurstThisRequest) {
                            $burstPenalty = $this->configCache['burstPenaltyScore'];
                            $currentPatternScore = max($currentPatternScore, $burstPenalty);
                            Log::debug('Citadel: Burst pattern penalty considered', ['burstPenalty' => $burstPenalty, 'currentScoreAfterBurstCheck' => $currentPatternScore]);

                            // Track burst violation ONLY if not already tracked as excess for this request
                            if (! $violationTrackedThisRequest) {
                                $this->trackViolationHistory($historyKey, $now, 0, $this->configCache['windowSize'], self::VIOLATION_TYPE_BURST);
                                $violationTrackedThisRequest = true;
                            }
                        }
                    }
                }
            }
            $currentPatternScore = max(0.0, $currentPatternScore);

            // Handle extreme request volumes (Overrides other scores if applicable)
            if ($requestCount >= $this->configCache['extremeRequestThreshold']) {
                Log::debug('Citadel: Extremely high request count detected, applying max frequency score', [
                    'requestCount' => $requestCount,
                    'threshold' => $this->configCache['extremeRequestThreshold'],
                ]);
                // Ensure violation is tracked if not already
                if (! $violationTrackedThisRequest && $requestCount > $this->configCache['maxRequestsPerWindow']) {
                    $excess = $requestCount - $this->configCache['maxRequestsPerWindow'];
                    $this->trackViolationHistory($historyKey, $now, $excess, $this->configCache['windowSize'], self::VIOLATION_TYPE_EXCESS);
                }
                $finalScore = $this->configCache['maxFrequencyScore'];
                $this->dataStore->setValue($cacheKey, $finalScore, $this->configCache['ttlBufferMultiplier']);

                return $finalScore;
            }

            // 4. Get the final score based on the potentially updated history.
            $finalScoreFromHistory = $this->getHistoricalScore($historyKey);

            // Determine the final score
            if ($violationTrackedThisRequest) {
                // If we tracked a violation this request, the history score
                // already incorporates the latest violation's impact.
                $totalScore = $finalScoreFromHistory;
            } else {
                // If no violation was tracked this request, the final score should be
                // the higher of any existing historical penalty OR the score calculated
                // based *purely* on the current request's pattern (e.g., regular pattern detected).
                $totalScore = max($finalScoreFromHistory, $currentPatternScore);
            }

            // Apply final score cap
            $totalScore = min($totalScore, $this->configCache['maxFrequencyScore']);
            Log::debug('Citadel: Final burstiness score calculated', [
                'currentPatternScore' => $currentPatternScore,
                'finalScoreFromHistory' => $finalScoreFromHistory,
                'violationTrackedThisRequest' => $violationTrackedThisRequest,
                'finalScore' => $totalScore,
            ]);

            // 5. Cache the final score
            if ($totalScore > 0.0) {
                $this->dataStore->setValue($cacheKey, $totalScore, $this->configCache['ttlBufferMultiplier']);
            } else {
                $this->dataStore->setValue($cacheKey, 0.0, 1); // Use constant for short TTL
            }

            return $totalScore;

        } catch (\Exception $e) {
            Log::error('Citadel: BurstinessAnalyzer exception', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'fingerprint' => $fingerprint,
            ]);

            return 0.0;
        }
    }

    /**
     * Detect the pattern type based on timestamps and stored pattern data
     */
    protected function detectPatternType(array $timestamps, string $patternKey): string
    {
        Log::debug('Citadel: Detecting pattern type', [
            'timestamps' => $timestamps,
            'patternKey' => $patternKey,
            'timestampCount' => count($timestamps),
            'minSamplesNeeded' => $this->configCache['minSamplesForPatternDetection'],
        ]);

        // 1. Check stored pattern data first (takes precedence)
        $patternData = $this->dataStore->getValue($patternKey);
        if (is_array($patternData) && isset($patternData['cv_history']) && is_array($patternData['cv_history'])) {
            Log::debug('Citadel: Found existing pattern data', ['pattern_data' => $patternData]);
            $cvHistory = $patternData['cv_history'];
            if (count($cvHistory) > 0) {
                $avgCV = array_sum($cvHistory) / count($cvHistory);
                Log::debug('Citadel: Evaluating pattern regularity from stored data', [
                    'avgCV' => $avgCV,
                    'veryRegularThreshold' => $this->configCache['veryRegularThreshold'],
                    'isVeryRegular' => ($avgCV < $this->configCache['veryRegularThreshold']),
                    'cvHistory' => $cvHistory,
                ]);
                if ($avgCV < $this->configCache['veryRegularThreshold']) {
                    Log::debug('Citadel: Detected regular pattern from stored cv_history', ['avg_cv' => $avgCV]);

                    return self::PATTERN_REGULAR;
                }
            }
        }

        // 2. If no stored data indicates regularity, check if the current pattern is well-spaced
        if ($this->isWellSpacedPattern($timestamps)) {
            Log::debug('Citadel: Detected well-spaced pattern (no conflicting stored data)');

            return self::PATTERN_NORMAL;
        }

        // 3. If not well-spaced, analyze current timestamps for regularity
        if (count($timestamps) >= $this->configCache['minSamplesForPatternDetection']) {
            $numericTimestamps = array_map('floatval', $timestamps);
            sort($numericTimestamps);

            $intervals = [];
            for ($i = 1; $i < count($numericTimestamps); $i++) {
                $intervals[] = $numericTimestamps[$i] - $numericTimestamps[$i - 1];
            }

            if (count($intervals) >= 2) {
                $mean = array_sum($intervals) / count($intervals);
                $variance = 0.0;

                if ($mean > 0) {
                    $squaredDiffs = array_map(function ($x) use ($mean) {
                        return pow($x - $mean, 2);
                    }, $intervals);
                    $variance = array_sum($squaredDiffs) / count($intervals);
                }

                $stdDev = sqrt($variance);
                $cv = ($mean > 0) ? $stdDev / $mean : 0;

                Log::debug('Citadel: Pattern statistics calculated', [
                    'intervals' => $intervals,
                    'mean' => $mean,
                    'stdDev' => $stdDev,
                    'coefficientOfVariation' => $cv,
                    'veryRegularThreshold' => $this->configCache['veryRegularThreshold'],
                    'isVeryRegular' => ($cv < $this->configCache['veryRegularThreshold']),
                ]);

                if ($cv < $this->configCache['veryRegularThreshold']) {
                    // Update pattern history with new CV value
                    $patternData = $this->dataStore->getValue($patternKey) ?? [];
                    if (! is_array($patternData)) {
                        $patternData = [];
                    }

                    if (! isset($patternData['cv_history']) || ! is_array($patternData['cv_history'])) {
                        $patternData['cv_history'] = [];
                    }

                    $patternData['cv_history'][] = $cv;
                    // Keep history limited to configured size
                    if (count($patternData['cv_history']) > $this->configCache['patternHistorySize']) {
                        $patternData['cv_history'] = array_slice(
                            $patternData['cv_history'],
                            -$this->configCache['patternHistorySize']
                        );
                    }

                    // Store updated pattern data with longer TTL to ensure it persists between test runs
                    $this->dataStore->setValue(
                        $patternKey,
                        $patternData,
                        $this->calculateTTL($this->configCache['windowSize'] * $this->configCache['historyTtlMultiplier'])
                    );

                    Log::debug('Citadel: Detected regular pattern based on statistics');

                    return self::PATTERN_REGULAR;
                }
            }
        }

        // 4. Default: If none of the above, assume Burst/Excess
        Log::debug('Citadel: Default pattern type (burst/excess) used');

        return self::PATTERN_BURST;
    }

    /**
     * Check if timestamps represent a normal, well-spaced user pattern
     */
    protected function isWellSpacedPattern(array $timestamps): bool
    {
        $count = count($timestamps);
        $maxRequests = $this->configCache['maxRequestsPerWindow'];
        $minInterval = $this->configCache['minInterval'];

        // Basic checks: Not enough data or too many requests
        if ($count < 2) {
            return true; // Not enough data to determine a pattern, assume normal
        }
        if ($count > $maxRequests) {
            Log::debug('Citadel: Too many requests to be considered well-spaced', [
                'timestampCount' => $count,
                'maxRequestsPerWindow' => $maxRequests,
            ]);

            return false;
        }

        $numericTimestamps = array_map('floatval', $timestamps);
        sort($numericTimestamps);

        Log::debug('Citadel: Checking if pattern is well-spaced', [
            'timestamps' => $numericTimestamps,
            'minRequiredInterval' => $minInterval,
            'timestampCount' => $count,
        ]);

        $allIntervalsGood = true;
        $shortIntervalFound = false;
        $shortIntervalIndex = -1;

        // Iterate through all intervals between timestamps
        for ($i = 1; $i < $count; $i++) {
            $interval = $numericTimestamps[$i] - $numericTimestamps[$i - 1];
            $isIntervalWellSpaced = ($interval >= $minInterval);

            Log::debug('Citadel: Interval check', [
                'index' => $i,
                'interval' => $interval,
                'minRequiredInterval' => $minInterval,
                'isWellSpaced' => $isIntervalWellSpaced,
            ]);

            if (! $isIntervalWellSpaced) {
                // If we find a second short interval, it's definitely not well-spaced
                if ($shortIntervalFound) {
                    Log::debug('Citadel: Multiple short intervals found, not well-spaced.');

                    return false;
                }
                // Record the first short interval found
                $allIntervalsGood = false;
                $shortIntervalFound = true;
                $shortIntervalIndex = $i;
            }
        }

        // Case 1: All intervals were >= minInterval. Clearly well-spaced.
        if ($allIntervalsGood) {
            Log::debug('Citadel: All intervals are well-spaced.');

            return true;
        }

        // Case 2: Only one short interval was found, and it was the *last* one.
        // This represents the current request being close to the previous one,
        // but the history before that was normal, and the request count is within limits.
        // Consider this well-spaced for now; subsequent close requests will trigger penalties.
        if ($shortIntervalFound && $shortIntervalIndex === ($count - 1)) {
            Log::debug('Citadel: Only the last interval was short, considered well-spaced for now.');

            return true;
        }

        // Case 3: A short interval occurred earlier, or multiple short intervals occurred.
        // This is not a well-spaced pattern.
        Log::debug('Citadel: Pattern not considered well-spaced.', [
            'allIntervalsGood' => $allIntervalsGood,
            'shortIntervalFound' => $shortIntervalFound,
            'shortIntervalIndex' => $shortIntervalIndex,
            'count' => $count,
        ]);

        return false;
    }

    /**
     * Detect burst patterns in the timestamp array
     */
    protected function detectBurst(array $timestamps, int $minInterval): bool
    {
        if (count($timestamps) < 2) {
            Log::debug('Citadel: Not enough timestamps for burst detection', [
                'timestampCount' => count($timestamps),
            ]);

            return false;
        }

        $numericTimestamps = array_map('floatval', $timestamps);
        sort($numericTimestamps);

        Log::debug('Citadel: Checking for burst patterns', [
            'timestamps' => $numericTimestamps,
            'minInterval' => $minInterval,
        ]);

        // Look for any consecutive timestamps that are too close together
        for ($i = 1; $i < count($numericTimestamps); $i++) {
            $interval = $numericTimestamps[$i] - $numericTimestamps[$i - 1];
            if ($interval < $minInterval) {
                Log::debug('Citadel: Burst pattern detected', [
                    'interval' => $interval,
                    'minInterval' => $minInterval,
                    'index' => $i,
                    'timestamp1' => $numericTimestamps[$i - 1],
                    'timestamp2' => $numericTimestamps[$i],
                ]);

                // We've found a burst pattern - immediately return true
                return true;
            }
        }

        Log::debug('Citadel: No burst pattern detected');

        return false;
    }

    /**
     * Check if all intervals except the last one are well-spaced
     */
    protected function isOtherwiseWellSpaced(array $timestamps, int $minInterval): bool
    {
        $count = count($timestamps);

        // Need at least 3 timestamps (2 intervals) to check
        if ($count < 3) {
            return true; // Not enough data to determine a pattern
        }

        // Check all intervals except the last one
        for ($i = 1; $i < $count - 1; $i++) {
            $interval = $timestamps[$i] - $timestamps[$i - 1];
            if ($interval < $minInterval) {
                return false; // Found another burst earlier in the sequence
            }
        }

        return true; // All other intervals are well-spaced
    }

    /**
     * Track a violation (excessive requests, burst, etc.) in history.
     * Renamed from trackExcessiveRequestHistory.
     */
    protected function trackViolationHistory(string $historyKey, int $timestamp, int $excess, int $windowSize, string $violationType = self::VIOLATION_TYPE_EXCESS): void
    {
        // Get existing history or create new
        $history = $this->dataStore->getValue($historyKey) ?? [
            'last_violation' => 0,
            'violation_count' => 0,
            'max_excess' => 0,
            'total_excess' => 0,
            'violations' => [],
        ];

        // Ensure history has expected structure
        if (! is_array($history)) {
            $history = [
                'last_violation' => 0,
                'violation_count' => 0,
                'max_excess' => 0,
                'total_excess' => 0,
                'violations' => [],
            ];
        }

        if (! isset($history['violations']) || ! is_array($history['violations'])) {
            $history['violations'] = [];
        }

        // Track this specific violation with timestamp and type
        $history['violations'][] = [
            'timestamp' => $timestamp,
            'excess' => $excess, // Keep excess for potential future use, even if 0 for bursts
            'type' => $violationType, // Add violation type
        ];

        // Keep only the last 10 violations in the history
        if (count($history['violations']) > 10) {
            $history['violations'] = array_slice($history['violations'], -10);
        }

        // Update aggregate history data
        $history['last_violation'] = $timestamp;

        // Critical: Always increment violation count - this ensures proper penalty escalation
        $history['violation_count'] = ($history['violation_count'] ?? 0) + 1;

        // Only update excess stats if it was an excess violation and excess > 0
        if ($violationType === self::VIOLATION_TYPE_EXCESS && $excess > 0) {
            $history['max_excess'] = max($history['max_excess'] ?? 0, $excess);
            $history['total_excess'] = ($history['total_excess'] ?? 0) + $excess;
        } else {
            // Ensure these keys exist even if not updated
            $history['max_excess'] = $history['max_excess'] ?? 0;
            $history['total_excess'] = $history['total_excess'] ?? 0;
        }

        // Apply a longer TTL to ensure history persists between test runs
        $ttl = max(3600, (int) ($windowSize / 1000 * $this->configCache['historyTtlMultiplier']));
        $this->dataStore->setValue($historyKey, $history, $ttl);

        Log::debug('Citadel: Updated violation history', [
            'historyKey' => $historyKey,
            'violationType' => $violationType, // Add type to log
            'violationCount' => $history['violation_count'],
            'totalExcess' => $history['total_excess'],
            'maxExcess' => $history['max_excess'],
            'violationsTracked' => count($history['violations']),
        ]);
    }

    /**
     * Calculate score based on historical violations
     */
    protected function getHistoricalScore(string $historyKey): float
    {
        $history = $this->dataStore->getValue($historyKey);
        Log::debug('Citadel: Checking historical violations', [
            'historyKey' => $historyKey,
            'history' => $history,
        ]);

        if (! $history || ! is_array($history)) {
            return 0.0;
        }

        $score = 0.0;
        $violationCount = $history['violation_count'] ?? 0;

        Log::debug('Citadel: Calculating history-based score', [
            'violationCount' => $violationCount,
            'minViolationsForPenalty' => $this->configCache['minViolationsForPenalty'],
            'maxExcess' => $history['max_excess'] ?? 0,
            'totalExcess' => $history['total_excess'] ?? 0,
        ]);

        // Apply penalties for repeat offenders - even if there's just one violation
        if ($violationCount >= $this->configCache['minViolationsForPenalty']) {
            // Base penalty that increases with violation count
            // Ensure at least the burst penalty score for the first violation
            $baseScore = $this->configCache['burstPenaltyScore'];

            // For multiple violations, increase the base score progressively using a non-linear function
            if ($violationCount > 1) {
                // Use a more aggressive multiplier for repeat offenders that scales with violation count
                // This ensures each subsequent offense has a higher penalty than the previous one
                $multiplier = self::HISTORY_MULTIPLIER_BASE + (($violationCount - 1) * self::HISTORY_PENALTY_INCREMENT);
                $baseScore *= $multiplier;

                Log::debug('Citadel: Applied progressive multiplier for repeat violations', [
                    'violationCount' => $violationCount,
                    'multiplier' => $multiplier,
                    'adjustedBaseScore' => $baseScore,
                ]);
            }

            $score += $baseScore;

            Log::debug('Citadel: Applied escalating penalty for violations', [
                'violationCount' => $violationCount,
                'baseScore' => $baseScore,
                'runningScore' => $score,
            ]);

            // For multiple violations, apply additional penalties based on recency
            if ($violationCount > 1) {
                // Check the time distribution of violations to detect persistent abusers
                // This adds a penalty that grows with each repeat violation
                $extraScore = $baseScore * ($violationCount * 0.1) * self::REPEAT_VIOLATION_MULTIPLIER;
                $score += $extraScore;

                Log::debug('Citadel: Applied additional penalty for repeat violations', [
                    'violationCount' => $violationCount,
                    'extraScore' => $extraScore,
                    'repeatMultiplier' => self::REPEAT_VIOLATION_MULTIPLIER,
                    'runningScore' => $score,
                ]);
            }
        }

        // Apply penalties for severe excess
        $maxExcess = $history['max_excess'] ?? 0;
        $totalExcess = $history['total_excess'] ?? 0;

        if ($maxExcess > 0) {
            $excessScore = min(
                $this->configCache['maxExcessScore'],
                $maxExcess * $this->configCache['excessMultiplier']
            );

            // Add additional penalty based on cumulative excess
            if ($totalExcess > $maxExcess) {
                $cumulativeFactor = min(2.0, 1.0 + (log($totalExcess / $maxExcess, 2) * 0.3));
                $excessScore *= $cumulativeFactor;
            }

            // Add penalties for repeated violations
            if ($violationCount > 1) {
                $excessScore *= (1.0 + ($violationCount * 0.15));
            }

            $score += $excessScore;
            Log::debug('Citadel: Applied penalty for historical excess', [
                'maxExcess' => $maxExcess,
                'totalExcess' => $totalExcess,
                'violationCount' => $violationCount,
                'excessScore' => $excessScore,
                'runningScore' => $score,
            ]);
        }

        // Cap at max violation score
        $score = min($score, $this->configCache['maxViolationScore']);

        Log::debug('Citadel: Final historical score', [
            'finalScore' => $score,
            'violationCount' => $violationCount,
        ]);

        return $score;
    }

    /**
     * Get current time in milliseconds
     */
    protected function getCurrentTimeInMilliseconds(): int
    {
        return (int) round(microtime(true) * 1000);
    }

    /**
     * Calculate TTL based on window size
     */
    protected function calculateTTL(int $windowSize): int
    {
        return (int) ($windowSize / 1000 * $this->configCache['ttlBufferMultiplier']);
    }

    /**
     * Generate consistent key names for Redis/storage
     */
    protected function generateKeyName(string $suffix, string $type): string
    {
        return self::KEY_PREFIX.":{$suffix}:{$type}";
    }
}
