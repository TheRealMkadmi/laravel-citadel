<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;

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
     * Scoring constants
     */
    private const BASE_LOGARITHM = 2.0;
    private const SEVERE_EXCESS_DIVISOR = 5.0;
    private const GROWTH_FACTOR_MULTIPLIER = 2.0;
    private const GROWTH_FACTOR_BASE = 1.0;
    private const UNIQUE_PATTERN_SCORE_MODIFIER = 0.1;
    private const INTERVAL_DIVISOR = 10;

    /**
     * Whether this analyzer scans request payload
     */
    protected bool $scansPayload = false;

    /**
     * Whether this analyzer is active
     */
    protected bool $active = false;

    /**
     * Cache of configuration values
     */
    protected array $configCache = [];

    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);
        $this->enabled = config(CitadelConfig::KEY_BURSTINESS . '.enable_burstiness_analyzer', true);
        $this->cacheTtl = config(CitadelConfig::KEY_CACHE . '.burst_analysis_ttl', 3600);
        $this->loadConfigValues();
    }

    /**
     * Load configuration values into a cache for faster access
     */
    protected function loadConfigValues(): void
    {
        $this->configCache = [
            'windowSize' => (int) config(CitadelConfig::KEY_BURSTINESS . '.window_size', 60000),
            'minInterval' => (int) config(CitadelConfig::KEY_BURSTINESS . '.min_interval', 5000),
            'maxRequestsPerWindow' => (int) config(CitadelConfig::KEY_BURSTINESS . '.max_requests_per_window', 5),
            'extremeRequestThreshold' => (int) config(CitadelConfig::KEY_BURSTINESS . '.extreme_request_threshold', 15),
            'excessRequestScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.excess_request_score', 10),
            'burstPenaltyScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.burst_penalty_score', 20),
            'maxFrequencyScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.max_frequency_score', 100),
            'veryRegularThreshold' => (float) config(CitadelConfig::KEY_BURSTINESS . '.very_regular_threshold', 0.1),
            'somewhatRegularThreshold' => (float) config(CitadelConfig::KEY_BURSTINESS . '.somewhat_regular_threshold', 0.25),
            'veryRegularScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.very_regular_score', 30),
            'somewhatRegularScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.somewhat_regular_score', 15),
            'patternHistorySize' => (int) config(CitadelConfig::KEY_BURSTINESS . '.pattern_history_size', 5),
            'historyTtlMultiplier' => (int) config(CitadelConfig::KEY_BURSTINESS . '.history_ttl_multiplier', 6),
            'minViolationsForPenalty' => (int) config(CitadelConfig::KEY_BURSTINESS . '.min_violations_for_penalty', 1),
            'maxViolationScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.max_violation_score', 50),
            'severeExcessThreshold' => (int) config(CitadelConfig::KEY_BURSTINESS . '.severe_excess_threshold', 10),
            'maxExcessScore' => (float) config(CitadelConfig::KEY_BURSTINESS . '.max_excess_score', 30),
            'excessMultiplier' => (float) config(CitadelConfig::KEY_BURSTINESS . '.excess_multiplier', 2),
            'ttlBufferMultiplier' => (int) config(CitadelConfig::KEY_BURSTINESS . '.ttl_buffer_multiplier', 2),
            'minSamplesForPatternDetection' => (int) config(CitadelConfig::KEY_BURSTINESS . '.min_samples_for_pattern', 3),
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
        $cacheKey = self::CACHE_PREFIX . ":{$fingerprint}";
        
        // Check cache for rapid subsequent requests
        $cachedScore = $this->dataStore->getValue($cacheKey);
        if ($cachedScore !== null) {
            Log::debug('Citadel: Using cached burstiness score', [
                'fingerprint' => $fingerprint,
                'score' => (float)$cachedScore
            ]);
            return (float) $cachedScore;
        }

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
            'timestamp' => $now
        ]);

        try {
            // Add the current timestamp to the request history
            $this->dataStore->zAdd($requestsKey, $now, $now);
            $this->dataStore->expire($requestsKey, $this->calculateTTL($this->configCache['windowSize']));
            
            // Clean up old timestamps outside the window
            $this->dataStore->zremrangebyscore($requestsKey, '-inf', $now - $this->configCache['windowSize']);
            
            // Get request count and timestamps
            $requestCount = $this->dataStore->zCard($requestsKey);
            $recentTimestamps = $this->dataStore->zRange($requestsKey, 0, -1);
            
            Log::debug('Citadel: Request history details', [
                'requestCount' => $requestCount,
                'windowSize' => $this->configCache['windowSize'],
                'timestampsCount' => count($recentTimestamps),
                'timestamps' => $recentTimestamps,
            ]);
            
            // ---------------------------------------------------------------
            // First, determine the pattern type before any other calculations
            // This ensures pattern detection takes priority over other scoring
            // ---------------------------------------------------------------
            
            // First check for well-spaced normal patterns directly
            // This needs to be done before excessive request check
            if ($this->isWellSpacedPattern($recentTimestamps)) {
                Log::debug('Citadel: Normal pattern detected, returning 0');
                $this->dataStore->setValue($cacheKey, 0.0, $this->configCache['ttlBufferMultiplier']);
                return 0.0;
            }
            
            // Handle extreme request volumes next
            if ($requestCount >= $this->configCache['extremeRequestThreshold']) {
                Log::debug('Citadel: Extremely high request count detected, applying max frequency score', [
                    'requestCount' => $requestCount,
                    'extremeRequestThreshold' => $this->configCache['extremeRequestThreshold'],
                    'maxFrequencyScore' => $this->configCache['maxFrequencyScore']
                ]);
                
                $this->dataStore->setValue($cacheKey, $this->configCache['maxFrequencyScore'], $this->configCache['ttlBufferMultiplier']);
                return $this->configCache['maxFrequencyScore'];
            }
            
            // Handle historical penalties
            $historyScore = $this->getHistoricalScore($historyKey);
            if ($historyScore > 0) {
                Log::debug('Citadel: Using historical score', [
                    'historyScore' => $historyScore,
                    'historyKey' => $historyKey
                ]);
                // Store the calculated score with a short TTL
                $this->dataStore->setValue($cacheKey, $historyScore, $this->configCache['ttlBufferMultiplier']);
                return $historyScore;
            }

            // Check if it's a regular pattern
            $patternType = $this->detectPatternType($recentTimestamps, $patternKey);
            Log::debug('Citadel: Pattern type detected', [
                'patternType' => $patternType
            ]);
            
            // Initialize score
            $score = 0.0;
            
            // For regular automated patterns, return the veryRegularScore immediately
            if ($patternType === self::PATTERN_REGULAR) {
                $score = $this->configCache['veryRegularScore'];
                
                // Add request-count based modifier to ensure scores differ with volume
                // even for otherwise similar pattern types
                if ($requestCount > $this->configCache['maxRequestsPerWindow']) {
                    $excess = $requestCount - $this->configCache['maxRequestsPerWindow'];
                    // Add a small unique increment based on request count
                    $score += $excess * self::UNIQUE_PATTERN_SCORE_MODIFIER;
                }
                
                Log::debug('Citadel: Regular pattern detected, using modified veryRegularScore', [
                    'score' => $score,
                    'requestCount' => $requestCount,
                    'baseScore' => $this->configCache['veryRegularScore']
                ]);
                $this->dataStore->setValue($cacheKey, $score, $this->configCache['ttlBufferMultiplier']);
                return $score;
            }
            
            // Frequency analysis - too many requests in time window
            if ($requestCount > $this->configCache['maxRequestsPerWindow']) {
                $excess = $requestCount - $this->configCache['maxRequestsPerWindow'];
                
                // Apply progressive scoring that properly scales with excess request count
                $baseExcessScore = $this->configCache['excessRequestScore'] * $excess;
                
                // Add a logarithmic component for non-linear growth
                $growthFactor = self::GROWTH_FACTOR_BASE;
                if ($excess > 1) {
                    // Enhanced logarithmic scaling to ensure better differentiation between request counts
                    $growthFactor = self::GROWTH_FACTOR_BASE + (log($excess, self::BASE_LOGARITHM) * self::GROWTH_FACTOR_MULTIPLIER);
                }
                
                // Create a progressive scoring that grows more than linearly with excess count
                $progressiveScore = $baseExcessScore * $growthFactor;
                
                Log::debug('Citadel: Progressive scoring calculation', [
                    'excess' => $excess,
                    'baseExcessScore' => $baseExcessScore,
                    'growthFactor' => $growthFactor,
                    'progressiveScore' => $progressiveScore
                ]);
                
                // Apply multiplier for very high request volume
                $severeExcessThreshold = $this->configCache['severeExcessThreshold'];
                if ($excess > $severeExcessThreshold) {
                    $excessMultiplier = $this->configCache['excessMultiplier'];
                    $severityFactor = 1.0 + (($excess - $severeExcessThreshold) / self::SEVERE_EXCESS_DIVISOR);
                    $progressiveScore *= $excessMultiplier * $severityFactor;
                    
                    Log::debug('Citadel: Severe excess multiplier applied', [
                        'excessMultiplier' => $excessMultiplier,
                        'severityFactor' => $severityFactor,
                        'adjustedScore' => $progressiveScore
                    ]);
                }
                
                // Cap at max frequency score
                $excessScore = min($progressiveScore, $this->configCache['maxFrequencyScore']);
                $score += $excessScore;
                
                Log::debug('Citadel: Excess request penalty applied', [
                    'requestCount' => $requestCount,
                    'maxRequestsPerWindow' => $this->configCache['maxRequestsPerWindow'],
                    'excess' => $excess,
                    'baseExcessScore' => $baseExcessScore,
                    'growthFactor' => $growthFactor,
                    'progressiveScore' => $progressiveScore,
                    'excessScore' => $excessScore,
                    'runningScore' => $score
                ]);
                
                $this->trackExcessiveRequestHistory($historyKey, $now, $excess, $this->configCache['windowSize']);
            }

            // Burst detection - check if requests are too close together
            if (count($recentTimestamps) >= 2) {
                $isBurst = $this->detectBurst($recentTimestamps, $this->configCache['minInterval']);
                if ($isBurst) {
                    $burstPenalty = $this->configCache['burstPenaltyScore'];
                    $score += $burstPenalty;
                    Log::debug('Citadel: Burst pattern detected, penalty applied', [
                        'burstPenalty' => $burstPenalty,
                        'runningScore' => $score
                    ]);
                    
                    // Record this burst violation
                    $burstHistoryKey = $this->generateKeyName($keySuffix, self::TYPE_BURST);
                    $burstCount = (int)($this->dataStore->getValue($burstHistoryKey) ?? 0) + 1;
                    $this->dataStore->setValue(
                        $burstHistoryKey, 
                        $burstCount, 
                        $this->calculateTTL($this->configCache['windowSize'])
                    );
                }
            }
            
            // Apply final score cap
            $totalScore = min($score, $this->configCache['maxFrequencyScore']);
            Log::debug('Citadel: Final burstiness score calculated', [
                'rawScore' => $score,
                'maxFrequencyScore' => $this->configCache['maxFrequencyScore'],
                'finalScore' => $totalScore
            ]);

            // Store the calculated score with a short TTL
            $this->dataStore->setValue($cacheKey, $totalScore, $this->configCache['ttlBufferMultiplier']);

            return (float) $totalScore;
        } catch (\Exception $e) {
            Log::error('Citadel: BurstinessAnalyzer exception', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'fingerprint' => $fingerprint
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
            'minSamplesNeeded' => $this->configCache['minSamplesForPatternDetection']
        ]);

        // First check if pattern data exists - this takes priority over timestamp analysis
        $patternData = $this->dataStore->getValue($patternKey);
        if (is_array($patternData) && isset($patternData['cv_history']) && is_array($patternData['cv_history'])) {
            Log::debug('Citadel: Found existing pattern data', ['pattern_data' => $patternData]);
            
            // Check if cv_history contains values below very regular threshold
            $cvHistory = $patternData['cv_history'];
            if (count($cvHistory) > 0) {
                $avgCV = array_sum($cvHistory) / count($cvHistory);
                if ($avgCV < $this->configCache['veryRegularThreshold']) {
                    Log::debug('Citadel: Detected regular pattern from stored cv_history', ['avg_cv' => $avgCV]);
                    return self::PATTERN_REGULAR;
                }
            }
        }

        // Check for well-spaced normal pattern
        if ($this->isWellSpacedPattern($timestamps)) {
            Log::debug('Citadel: Detected well-spaced pattern');
            return self::PATTERN_NORMAL;
        }

        // Analyze pattern based on timing regularity
        if (count($timestamps) >= $this->configCache['minSamplesForPatternDetection']) {
            $numericTimestamps = array_map('floatval', $timestamps);
            sort($numericTimestamps);

            $intervals = [];
            for ($i = 1; $i < count($numericTimestamps); $i++) {
                $intervals[] = $numericTimestamps[$i] - $numericTimestamps[$i-1];
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
                    'veryRegularThreshold' => $this->configCache['veryRegularThreshold']
                ]);

                if ($cv < $this->configCache['veryRegularThreshold']) {
                    // Update pattern history with new CV value
                    $patternData = $this->dataStore->getValue($patternKey) ?? [];
                    if (!is_array($patternData)) {
                        $patternData = [];
                    }
                    
                    if (!isset($patternData['cv_history']) || !is_array($patternData['cv_history'])) {
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
                    
                    // Store updated pattern data
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

        // Default - not a special pattern type
        Log::debug('Citadel: Default pattern type (burst) used');
        return self::PATTERN_BURST;
    }

    /**
     * Check if timestamps represent a normal, well-spaced user pattern
     */
    protected function isWellSpacedPattern(array $timestamps): bool
    {
        // Need at least 2 timestamps to check spacing
        if (count($timestamps) < 2) {
            return false;
        }

        // If the request count exceeds the maximum allowed requests per window,
        // it's not considered well-spaced regardless of intervals
        if (count($timestamps) > $this->configCache['maxRequestsPerWindow']) {
            Log::debug('Citadel: Too many requests to be considered well-spaced', [
                'timestampCount' => count($timestamps),
                'maxRequestsPerWindow' => $this->configCache['maxRequestsPerWindow']
            ]);
            return false;
        }

        $numericTimestamps = array_map('floatval', $timestamps);
        sort($numericTimestamps);
        
        // Define what "well-spaced" means: timestamps are separated by at least minInterval
        $minRequiredInterval = $this->configCache['minInterval'];
        
        Log::debug('Citadel: Checking if pattern is well-spaced', [
            'timestamps' => $numericTimestamps,
            'minRequiredInterval' => $minRequiredInterval,
            'timestampCount' => count($numericTimestamps)
        ]);
        
        // Check if all timestamps are sufficiently spaced apart
        $allWellSpaced = true;
        for ($i = 1; $i < count($numericTimestamps); $i++) {
            $interval = $numericTimestamps[$i] - $numericTimestamps[$i-1];
            Log::debug('Citadel: Interval check', [
                'index' => $i,
                'interval' => $interval,
                'minRequiredInterval' => $minRequiredInterval,
                'isWellSpaced' => ($interval >= $minRequiredInterval)
            ]);
            
            if ($interval < $minRequiredInterval) {
                $allWellSpaced = false;
                break;
            }
        }
        
        Log::debug('Citadel: Pattern well-spaced result', [
            'allWellSpaced' => $allWellSpaced
        ]);
        
        return $allWellSpaced;
    }
    
    /**
     * Detect burst patterns in the timestamp array
     */
    protected function detectBurst(array $timestamps, int $minInterval): bool
    {
        if (count($timestamps) < 2) {
            Log::debug('Citadel: Not enough timestamps for burst detection', [
                'timestampCount' => count($timestamps)
            ]);
            return false;
        }

        $numericTimestamps = array_map('floatval', $timestamps);
        sort($numericTimestamps);

        Log::debug('Citadel: Checking for burst patterns', [
            'timestamps' => $numericTimestamps,
            'minInterval' => $minInterval
        ]);

        // Look for any consecutive timestamps that are too close together
        for ($i = 1; $i < count($numericTimestamps); $i++) {
            $interval = $numericTimestamps[$i] - $numericTimestamps[$i-1];
            if ($interval < $minInterval) {
                Log::debug('Citadel: Burst pattern detected', [
                    'interval' => $interval,
                    'minInterval' => $minInterval,
                    'index' => $i,
                    'timestamp1' => $numericTimestamps[$i-1],
                    'timestamp2' => $numericTimestamps[$i]
                ]);
                
                // If this is the final timestamp in an otherwise well-spaced sequence,
                // be more lenient to avoid penalizing legitimate users
                if ($i === count($numericTimestamps) - 1) {
                    // Check if all previous intervals were well-spaced
                    if ($this->isOtherwiseWellSpaced($numericTimestamps, $minInterval)) {
                        // For normal user traffic (vs automated), a single burst at the end
                        // is likely just normal user behavior with an occasional fast follow-up click
                        // Don't consider it a burst pattern if it's a single occurrence at the end
                        Log::debug('Citadel: Ignoring isolated burst at end of normal sequence', [
                            'timestampCount' => count($numericTimestamps)
                        ]);
                        return false;
                    }
                }
                
                return true; // Found a burst pattern
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
            $interval = $timestamps[$i] - $timestamps[$i-1];
            if ($interval < $minInterval) {
                return false; // Found another burst earlier in the sequence
            }
        }
        
        return true; // All other intervals are well-spaced
    }
    
    protected function trackExcessiveRequestHistory(string $historyKey, int $timestamp, int $excess, int $windowSize): void
    {
        // Get existing history or create new
        $history = $this->dataStore->getValue($historyKey) ?? [
            'last_violation' => 0,
            'violation_count' => 0,
            'max_excess' => 0,
            'total_excess' => 0,
        ];
        
        // Ensure history has expected structure
        if (!is_array($history)) {
            $history = [
                'last_violation' => 0,
                'violation_count' => 0,
                'max_excess' => 0,
                'total_excess' => 0,
            ];
        }

        // Update history data
        $history['last_violation'] = $timestamp;
        $history['violation_count'] = ($history['violation_count'] ?? 0) + 1;
        $history['max_excess'] = max($history['max_excess'] ?? 0, $excess);
        $history['total_excess'] = ($history['total_excess'] ?? 0) + $excess;

        // Store with extended TTL
        $this->dataStore->setValue(
            $historyKey,
            $history,
            (int) ($windowSize / 1000 * $this->configCache['historyTtlMultiplier'])
        );
    }

    /**
     * Calculate score based on historical violations
     */
    protected function getHistoricalScore(string $historyKey): float
    {
        $history = $this->dataStore->getValue($historyKey);
        Log::debug('Citadel: Checking historical violations', [
            'historyKey' => $historyKey,
            'history' => $history
        ]);
        
        if (! $history || !is_array($history)) {
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
        
        // Apply penalties for repeat offenders
        if ($violationCount >= $this->configCache['minViolationsForPenalty']) {
            $score += $this->configCache['burstPenaltyScore'];
            Log::debug('Citadel: Applied basic penalty for violations', [
                'baseScore' => $this->configCache['burstPenaltyScore'],
                'runningScore' => $score
            ]);
            
            // For multiple violations, apply more aggressive scaling
            if ($violationCount > 1) {
                $extraScore = min(
                    $this->configCache['maxViolationScore'] - $this->configCache['burstPenaltyScore'],
                    $this->configCache['burstPenaltyScore'] * (pow($violationCount, 1.5) - 1)
                );
                $score += $extraScore;
                Log::debug('Citadel: Applied additional penalty for multiple violations', [
                    'extraScore' => $extraScore,
                    'runningScore' => $score
                ]);
            }
        }
        
        // Apply penalties for severe excess
        $maxExcess = $history['max_excess'] ?? 0;
        if ($maxExcess > $this->configCache['severeExcessThreshold']) {
            $excessScore = min(
                $this->configCache['maxExcessScore'],
                $maxExcess * $this->configCache['excessMultiplier']
            );
            $score += $excessScore;
            Log::debug('Citadel: Applied penalty for severe excess', [
                'excessScore' => $excessScore,
                'runningScore' => $score
            ]);
        }

        Log::debug('Citadel: Final historical score', [
            'finalScore' => $score
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
        return self::KEY_PREFIX . ":{$suffix}:{$type}";
    }
}
