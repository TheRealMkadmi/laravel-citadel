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
    private const KEY_PREFIX = 'burst';
    protected bool $scansPayload = false;
    protected bool $active = false;
    protected array $configCache = [];

    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);
        $this->enabled = config('citadel.burstiness.enable_burstiness_analyzer', true);
        $this->cacheTtl = config('citadel.cache.burst_analysis_ttl', 3600);
        $this->loadConfigValues();
    }

    protected function loadConfigValues(): void
    {
        $this->configCache = [
            'windowSize' => (int)config('citadel.burstiness.window_size', 60000),
            'minInterval' => (int)config('citadel.burstiness.min_interval', 5000),
            'maxRequestsPerWindow' => (int)config('citadel.burstiness.max_requests_per_window', 5),
            'excessRequestScore' => (float)config('citadel.burstiness.excess_request_score', 10),
            'burstPenaltyScore' => (float)config('citadel.burstiness.burst_penalty_score', 20),
            'maxFrequencyScore' => (float)config('citadel.burstiness.max_frequency_score', 100),
            'veryRegularThreshold' => (float)config('citadel.burstiness.very_regular_threshold', 0.1),
            'somewhatRegularThreshold' => (float)config('citadel.burstiness.somewhat_regular_threshold', 0.25),
            'veryRegularScore' => (float)config('citadel.burstiness.very_regular_score', 30),
            'somewhatRegularScore' => (float)config('citadel.burstiness.somewhat_regular_score', 15),
            'patternHistorySize' => (int)config('citadel.burstiness.pattern_history_size', 5),
            'historyTtlMultiplier' => (int)config('citadel.burstiness.history_ttl_multiplier', 6),
            'minViolationsForPenalty' => (int)config('citadel.burstiness.min_violations_for_penalty', 1),
            'maxViolationScore' => (float)config('citadel.burstiness.max_violation_score', 50),
            'severeExcessThreshold' => (int)config('citadel.burstiness.severe_excess_threshold', 10),
            'maxExcessScore' => (float)config('citadel.burstiness.max_excess_score', 30),
            'excessMultiplier' => (float)config('citadel.burstiness.excess_multiplier', 2),
            'ttlBufferMultiplier' => (int)config('citadel.burstiness.ttl_buffer_multiplier', 2),
            'minSamplesForPatternDetection' => (int)config('citadel.burstiness.min_samples_for_pattern', 3),
        ];
    }

    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            return 0.0;
        }

        $fingerprint = $request->getFingerprint();
        if (empty($fingerprint)) {
            return 0.0;
        }

        $cacheKey = "burstiness:{$fingerprint}";
        if (($cachedScore = $this->dataStore->getValue($cacheKey)) !== null) {
            return (float)$cachedScore;
        }

        $now = $this->getCurrentTimeInMilliseconds();
        $keySuffix = Str::substr(md5($fingerprint), 0, 12);
        $requestsKey = $this->generateKeyName($keySuffix, 'req');
        $patternKey = $this->generateKeyName($keySuffix, 'pat');
        $historyKey = $this->generateKeyName($keySuffix, 'hist');

        $results = $this->dataStore->pipeline(function ($pipe) use ($requestsKey, $now) {
            $pipe->zremrangebyscore($requestsKey, '-inf', $now - $this->configCache['windowSize']);
            $pipe->zadd($requestsKey, $now, $now);
            $pipe->expire($requestsKey, $this->calculateTTL($this->configCache['windowSize']));
            $pipe->zcard($requestsKey);
            $pipe->zrange($requestsKey, -5, -1);
        });

        $requestCount = $results[3] ?? 1;
        $recentTimestamps = $results[4] ?? [];
        $score = 0;

        // Frequency analysis
        if ($requestCount > $this->configCache['maxRequestsPerWindow']) {
            $excess = $requestCount - $this->configCache['maxRequestsPerWindow'];
            $score += min(
                $this->configCache['excessRequestScore'] * $excess,
                $this->configCache['maxFrequencyScore']
            );
            $this->trackExcessiveRequestHistory($historyKey, $now, $excess, $this->configCache['windowSize']);
        }

        // Burst detection
        if (count($recentTimestamps) >= 3 && $score < $this->configCache['maxFrequencyScore']) {
            if ($this->detectBurst($recentTimestamps, $this->configCache['minInterval'])) {
                $score += $this->configCache['burstPenaltyScore'];
            }

            // Pattern analysis
            if (count($recentTimestamps) >= $this->configCache['minSamplesForPatternDetection']) {
                $score += $this->analyzeRequestPatterns($recentTimestamps, $patternKey, $this->configCache['windowSize']);
            }
        }

        // Apply final score cap
        $score = min($score, $this->configCache['maxFrequencyScore']);

        // Historical penalties
        $historyScore = $this->getHistoricalScore($historyKey);
        $totalScore = min($score + $historyScore, $this->configCache['maxFrequencyScore']);

        $this->dataStore->setValue($cacheKey, $totalScore, min(60, $this->cacheTtl));
        return (float)$totalScore;
    }

    protected function detectBurst(array $timestamps, int $minInterval): bool
    {
        if (count($timestamps) < 2) {
            return false;
        }

        $numericTimestamps = array_map('intval', $timestamps);
        sort($numericTimestamps);

        $burstCount = 0;
        foreach (array_slice($numericTimestamps, 1) as $i => $timestamp) {
            if (($timestamp - $numericTimestamps[$i]) < $minInterval) {
                $burstCount++;
                if ($burstCount >= 2) {
                    return true;
                }
            }
        }
        return false;
    }

    protected function analyzeRequestPatterns(array $timestamps, string $patternKey, int $ttl): float
    {
        $numericTimestamps = array_map('intval', $timestamps);
        sort($numericTimestamps);
        $intervals = [];
        
        foreach (array_slice($numericTimestamps, 1) as $i => $timestamp) {
            $intervals[] = $timestamp - $numericTimestamps[$i];
        }

        if (count($intervals) >= 2) {
            $mean = array_sum($intervals) / count($intervals);
            $variance = array_sum(array_map(fn($x) => ($x - $mean) ** 2, $intervals)) / count($intervals);
            $cv = sqrt($variance) / ($mean ?: 1);

            $patternData = $this->dataStore->getValue($patternKey) ?? ['cv_history' => []];
            $patternData['cv_history'][] = $cv;
            
            if (count($patternData['cv_history']) > $this->configCache['patternHistorySize']) {
                array_shift($patternData['cv_history']);
            }
            
            $avgCV = count($patternData['cv_history']) > 0 
                ? array_sum($patternData['cv_history']) / count($patternData['cv_history']) 
                : 0;

            if ($avgCV < $this->configCache['veryRegularThreshold']) {
                return $this->configCache['veryRegularScore'];
            }
            if ($avgCV < $this->configCache['somewhatRegularThreshold']) {
                return $this->configCache['somewhatRegularScore'];
            }
        }
        return 0.0;
    }

    protected function trackExcessiveRequestHistory(string $historyKey, int $timestamp, int $excess, int $ttl): void
    {
        $history = $this->dataStore->getValue($historyKey) ?? [
            'last_violation' => 0,
            'violation_count' => 0,
            'max_excess' => 0,
            'total_excess' => 0
        ];

        $history['violation_count']++;
        $history['max_excess'] = max($history['max_excess'], $excess);
        $history['last_violation'] = $timestamp;
        
        $this->dataStore->setValue(
            $historyKey,
            $history,
            (int)($ttl / 1000 * $this->configCache['historyTtlMultiplier'])
        );
    }

    protected function getHistoricalScore(string $historyKey): float
    {
        $history = $this->dataStore->getValue($historyKey);
        if (!$history) return 0;

        $score = 0;
        if ($history['violation_count'] >= $this->configCache['minViolationsForPenalty']) {
            $score += min(
                $this->configCache['maxViolationScore'],
                pow($history['violation_count'], 1.5)
            );
        }

        if ($history['max_excess'] > $this->configCache['severeExcessThreshold']) {
            $score += min(
                $this->configCache['maxExcessScore'],
                $history['max_excess'] * $this->configCache['excessMultiplier']
            );
        }

        return (float)min($score, $this->configCache['maxFrequencyScore']);
    }

    protected function getCurrentTimeInMilliseconds(): int
    {
        return (int)round(microtime(true) * 1000);
    }

    protected function calculateTTL(int $windowSize): int
    {
        return (int)($windowSize / 1000 * $this->configCache['ttlBufferMultiplier']);
    }

    protected function generateKeyName(string $suffix, string $type): string
    {
        return self::KEY_PREFIX . ":$suffix:$type";
    }
}
