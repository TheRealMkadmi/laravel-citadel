<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class SpamminessAnalyzer extends AbstractAnalyzer
{
    /**
     * Config key prefix for spamminess analyzer
     */
    private const CONFIG_PREFIX = 'citadel.spamminess';

    /**
     * Weights for different spam detection techniques
     */
    protected array $weights;

    /**
     * Configuration for text analysis
     */
    protected array $textAnalysisConfig;

    /**
     * Cache for previously analyzed texts
     */
    protected array $analysisCache = [];

    /**
     * Indicates if this analyzer scans payload content.
     */
    protected bool $scansPayload = true;

    /**
     * This analyzer doesn't make external network requests.
     */
    protected bool $active = false;

    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);

        $this->enabled = config(self::CONFIG_PREFIX.'.enable_spamminess_analyzer', true);
        $this->cacheTtl = config(self::CONFIG_PREFIX.'.cache_ttl', 3600);

        // Use Laravel's config helper with constant references
        $this->loadConfigurationValues();
    }

    /**
     * Load all configuration values at once to prevent repeated config lookups
     */
    protected function loadConfigurationValues(): void
    {
        $this->weights = config(self::CONFIG_PREFIX.'.weights', [
            'gibberish_text' => 25.0,
            'repetitive_content' => 10.0,
            'suspicious_entropy' => 20.0,
            'statistical_anomaly' => 30.0,
        ]);

        $this->textAnalysisConfig = config(self::CONFIG_PREFIX.'.text_analysis', [
            'min_entropy_threshold' => 1.0,
            'max_entropy_threshold' => 4.0,
            'min_field_length' => 2,
            'max_repetition_ratio' => 0.4,
            'min_vowel_ratio' => 0.1,
            'consonant_sequence_threshold' => 4,
            'character_distribution_threshold' => 0.7,
            'zipf_deviation_threshold' => 0.4,
            'statistical_significance_threshold' => 0.05,
            'max_correlation_threshold' => 0.8,
        ]);
    }

    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            return 0.0;
        }

        // Generate a cache key for this fingerprint
        $fingerprint = $request->getFingerprint();
        $cacheKey = "spamminess:{$fingerprint}";

        // Check if we have a cached result
        $cachedScore = $this->dataStore->getValue($cacheKey);
        if ($cachedScore !== null) {
            return (float) $cachedScore;
        }

        $payload = $request->all();

        // Process all fields recursively, handling arrays and nested objects
        $score = $this->processPayload($payload);
        $maxScore = config(self::CONFIG_PREFIX.'.max_score', 100.0);
        $finalScore = min($score, $maxScore);

        // Cache the result
        $this->dataStore->setValue($cacheKey, $finalScore, $this->cacheTtl);

        return $finalScore;
    }

    /**
     * Process payload data recursively, detecting anomalies in all values
     */
    protected function processPayload(mixed $data, string $prefix = ''): float
    {
        $score = 0.0;

        if (is_array($data) || is_object($data)) {
            $data = Arr::wrap($data);

            // Skip processing very large payloads by sampling
            if (count($data) > 50) {
                $data = Arr::random($data, 50);
            }

            foreach ($data as $key => $value) {
                $currentPath = $prefix ? "{$prefix}.{$key}" : $key;
                $score += $this->processPayload($value, $currentPath);
            }
        } elseif (is_string($data)) {
            // Skip very large strings to prevent performance issues
            if (Str::length($data) > 10000) {
                $data = Str::substr($data, 0, 5000).Str::substr($data, -5000);
            }
            $score += $this->analyzeTextField($data);
        }

        return $score;
    }

    protected function analyzeTextField(string $text): float
    {
        // Create a hash key for caching
        $textHash = md5($text);

        // Check if we've already analyzed this text
        if (isset($this->analysisCache[$textHash])) {
            return $this->analysisCache[$textHash];
        }

        $score = 0.0;
        $text = Str::of($text)->trim();

        if ($text->length() < $this->textAnalysisConfig['min_field_length']) {
            return 0.0;
        }

        // Check for repetitive content
        if ($this->isRepetitiveContent($text->toString())) {
            $score += $this->weights['repetitive_content'];
        }

        // Calculate and evaluate entropy
        $entropy = $this->calculateShannonEntropy($text->toString());
        if ($this->isEntropyAnomalous($entropy)) {
            $score += $this->weights['suspicious_entropy'] * $this->calculateEntropyDeviation($entropy);
        }

        // Advanced statistical gibberish detection
        $gibberishScore = $this->calculateStatisticalGibberishScore($text->toString());
        if ($gibberishScore > 0) {
            $score += $this->weights['gibberish_text'] * $gibberishScore;
        }

        // Cache the result to avoid repeated analysis
        $this->analysisCache[$textHash] = $score;

        // Prevent memory issues by limiting cache size
        if (count($this->analysisCache) > 100) {
            // Remove random entries when cache gets too large
            $this->analysisCache = Arr::random($this->analysisCache, 50, true);
        }

        return $score;
    }

    /**
     * Calculate how much the entropy deviates from normal text range
     */
    protected function calculateEntropyDeviation(float $entropy): float
    {
        $minThreshold = $this->textAnalysisConfig['min_entropy_threshold'];
        $maxThreshold = $this->textAnalysisConfig['max_entropy_threshold'];

        if ($entropy < $minThreshold) {
            return 1 - ($entropy / $minThreshold);
        }

        if ($entropy > $maxThreshold) {
            return ($entropy - $maxThreshold) / $maxThreshold;
        }

        return 0;
    }

    protected function calculateShannonEntropy(string $text): float
    {
        $len = Str::length($text);
        if ($len === 0) {
            return 0.0;
        }

        $freq = [];
        // Optimize character splitting for UTF-8 using Laravel's Str helper
        $characters = Str::of($text)->split('//u');

        foreach ($characters as $ch) {
            if ($ch === '') {
                continue;
            }
            $freq[$ch] = Arr::get($freq, $ch, 0) + 1;
        }

        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    protected function isEntropyAnomalous(float $entropy): bool
    {
        return $entropy < $this->textAnalysisConfig['min_entropy_threshold'] ||
               $entropy > $this->textAnalysisConfig['max_entropy_threshold'];
    }

    protected function isRepetitiveContent(string $text): bool
    {
        // Check for character repetition
        $len = Str::length($text);
        if ($len === 0) {
            return false;
        }

        // Count consecutive repeated characters
        $repeats = 0;
        $lastChar = '';

        // Optimize character splitting for UTF-8 using Laravel's Str helper
        $characters = Str::of($text)->split('//u');

        foreach ($characters as $char) {
            if ($char === '') {
                continue;
            }
            if ($char === $lastChar) {
                $repeats++;
            }
            $lastChar = $char;
        }

        $repetitionRatio = $repeats / $len;

        // Check for word repetition patterns using Laravel collections
        $words = Str::of($text)
            ->explode(' ')
            ->filter()
            ->values();

        $wordCount = $words->count();

        if ($wordCount > 1) {
            $uniqueWords = $words->unique()->count();
            $uniqueRatio = $uniqueWords / $wordCount;

            // If there's a very low ratio of unique words, it's repetitive
            if ($uniqueRatio < 0.3 && $wordCount > 3) {
                return true;
            }
        }

        return $repetitionRatio > $this->textAnalysisConfig['max_repetition_ratio'];
    }

    /**
     * Calculate a statistical gibberish score using multiple numerical techniques
     * Returns a score between 0 and 1, where higher values indicate more likely gibberish
     */
    protected function calculateStatisticalGibberishScore(string $text): float
    {
        $textLower = Str::lower($text);
        $textLength = Str::length($textLower);

        if ($textLength < $this->textAnalysisConfig['min_field_length']) {
            return 0.0;
        }

        $scores = [];

        // 1. Vowel ratio analysis
        $scores[] = $this->vowelAnalysisScore($textLower);

        // 2. Consonant sequence analysis
        $scores[] = $this->consonantSequenceScore($textLower);

        // For longer texts, include more computationally intensive checks
        if ($textLength > 20) {
            // 3. Character distribution analysis
            $scores[] = $this->characterDistributionScore($textLower);

            // Only perform these expensive analyses on moderately sized texts
            if ($textLength < 1000) {
                // 4. Statistical n-gram analysis
                $scores[] = $this->statisticalNgramAnalysis($textLower);

                // 5. Zipf's law deviation analysis
                $scores[] = $this->zipfLawDeviationAnalysis($textLower);
            }
        }

        // Filter out null scores and calculate weighted average
        $validScores = Arr::where($scores, function ($score) {
            return $score !== null;
        });

        if (empty($validScores)) {
            return 0.0;
        }

        $weightedScore = array_sum($validScores) / count($validScores);

        return min(1.0, max(0.0, $weightedScore));
    }

    /**
     * Analyze vowel patterns in text
     */
    protected function vowelAnalysisScore(string $text): float
    {
        $vowels = preg_match_all('/[aeiouäëïöüáéíóúàèìòù]/i', $text);
        $len = Str::length($text);

        if ($len === 0) {
            return 0.0;
        }

        $vowelRatio = $vowels / $len;

        // Natural language typically has vowel ratio between 30-50%
        // Extreme values in either direction can indicate gibberish
        if ($vowelRatio < $this->textAnalysisConfig['min_vowel_ratio']) {
            return 1.0; // Strong indicator of gibberish
        }

        if ($vowelRatio > 0.6) {
            return 0.7; // Too many vowels is also suspicious
        }

        return 0.0;
    }

    /**
     * Detect unusually long consonant sequences
     */
    protected function consonantSequenceScore(string $text): float
    {
        $maxConsonantSeq = 0;
        $currentSeq = 0;

        $characters = Str::of($text)->split('//u');

        foreach ($characters as $char) {
            if ($char === '') {
                continue;
            }
            if (preg_match('/[bcdfghjklmnpqrstvwxyz]/i', $char)) {
                $currentSeq++;
                $maxConsonantSeq = max($maxConsonantSeq, $currentSeq);
            } else {
                $currentSeq = 0;
            }
        }

        $threshold = $this->textAnalysisConfig['consonant_sequence_threshold'];

        if ($maxConsonantSeq > $threshold) {
            return min(1.0, ($maxConsonantSeq - $threshold) / 4);
        }

        return 0.0;
    }

    /**
     * Analyze overall character distribution compared to expected distributions
     */
    protected function characterDistributionScore(string $text): float
    {
        // Get character frequency
        $charCount = $this->getCharacterFrequencies($text);
        $totalChars = array_sum($charCount);

        if ($totalChars < 5) {
            return 0.0;
        }

        // Calculate statistical measures on character distribution using Laravel collections
        $charDistribution = collect($charCount)->map(function ($count) use ($totalChars) {
            return $count / $totalChars;
        });

        // Calculate standard deviation of distribution using Laravel collection methods
        $mean = $charDistribution->avg();
        $variance = $charDistribution->map(function ($value) use ($mean) {
            return pow($value - $mean, 2);
        })->avg();

        $stdDev = sqrt($variance);

        // Calculate coefficient of variation (measure of relative variability)
        $cv = $mean > 0 ? $stdDev / $mean : 0;

        // Normalize to 0-1 score
        $threshold = $this->textAnalysisConfig['character_distribution_threshold'];
        $normalizedScore = min(1.0, $cv / $threshold);

        return $normalizedScore;
    }

    /**
     * Get character frequencies from text
     *
     * @return array<string, int>
     */
    protected function getCharacterFrequencies(string $text): array
    {
        $freq = [];
        $characters = Str::of(Str::lower($text))->split('//u');

        foreach ($characters as $ch) {
            if ($ch === '') {
                continue;
            }
            $freq[$ch] = Arr::get($freq, $ch, 0) + 1;
        }

        return $freq;
    }

    /**
     * Perform statistical analysis on n-grams to detect gibberish
     */
    protected function statisticalNgramAnalysis(string $text): float
    {
        $textLength = Str::length($text);
        if ($textLength < 4) {
            return 0.0;
        }

        // Extract bigrams and calculate their frequencies
        $bigramFrequencies = [];
        for ($i = 0; $i < $textLength - 1; $i++) {
            $bigram = Str::substr($text, $i, 2);
            $bigramFrequencies[$bigram] = Arr::get($bigramFrequencies, $bigram, 0) + 1;
        }

        // Calculate entropy of bigram distribution
        $bigramEntropy = 0;
        $totalBigrams = array_sum($bigramFrequencies);

        foreach ($bigramFrequencies as $count) {
            $p = $count / $totalBigrams;
            $bigramEntropy -= $p * log($p, 2);
        }

        // Calculate bigram transition likelihood
        // This measures how predictable the transitions between characters are
        $transitionScore = 0;
        $uniqueBigrams = count($bigramFrequencies);
        $expectedUniqueBigrams = min($textLength - 1, 26 * 26); // Max possible distinct bigrams

        // Transition predictability - ratio of actual vs expected unique bigrams
        $transitionPredictability = $uniqueBigrams / $expectedUniqueBigrams;

        // Combine measures - normalized between 0 and 1
        // Higher score = more likely to be gibberish
        $bigramEntropyScore = min(1.0, $bigramEntropy / 10); // Normalize entropy score

        // Score is high if:
        // 1. Bigram entropy is unusually high (randomness)
        // 2. Transition predictability is unusually high (pattern is too predictable or too random)
        $finalScore = ($bigramEntropyScore + abs($transitionPredictability - 0.5)) / 2;

        return $finalScore;
    }

    /**
     * Analyze character frequency distribution for deviation from Zipf's law
     * which is observed in natural language
     */
    protected function zipfLawDeviationAnalysis(string $text): float
    {
        $charFreq = $this->getCharacterFrequencies($text);

        // Need sufficient characters for meaningful analysis
        if (array_sum($charFreq) < 10) {
            return 0.0;
        }

        // Sort frequencies in descending order
        arsort($charFreq);
        $frequencies = array_values($charFreq);

        // Calculate expected Zipf distribution
        // In Zipf's law, frequency is proportional to 1/rank
        $expectedZipf = [];
        $firstFreq = $frequencies[0];

        for ($rank = 1; $rank <= count($frequencies); $rank++) {
            $expectedZipf[$rank - 1] = $firstFreq / $rank;
        }

        // Calculate correlation between observed and expected frequencies
        $correlation = $this->calculateCorrelation($frequencies, $expectedZipf);

        // Invert correlation - higher deviation = higher score
        // A correlation close to 1 means the text follows Zipf's law (natural language)
        // Lower correlation suggests gibberish
        $zipfDeviationThreshold = $this->textAnalysisConfig['zipf_deviation_threshold'];

        if ($correlation > $this->textAnalysisConfig['max_correlation_threshold']) {
            return 0.0; // Text follows Zipf's law well - likely natural
        }

        // Calculate score based on deviation from expected correlation
        $score = 1 - ($correlation / $this->textAnalysisConfig['max_correlation_threshold']);

        return min(1.0, max(0.0, $score));
    }

    /**
     * Calculate Pearson correlation coefficient between two arrays
     */
    protected function calculateCorrelation(array $x, array $y): float
    {
        $n = min(count($x), count($y));

        if ($n < 3) {
            return 0.0;
        }

        $x = array_slice($x, 0, $n);
        $y = array_slice($y, 0, $n);

        $sumX = array_sum($x);
        $sumY = array_sum($y);

        $sumXSq = array_sum(array_map(function ($val) {
            return pow($val, 2);
        }, $x));

        $sumYSq = array_sum(array_map(function ($val) {
            return pow($val, 2);
        }, $y));

        $productSum = 0;
        for ($i = 0; $i < $n; $i++) {
            $productSum += $x[$i] * $y[$i];
        }

        $numerator = $n * $productSum - $sumX * $sumY;
        $denominator = sqrt(($n * $sumXSq - pow($sumX, 2)) * ($n * $sumYSq - pow($sumY, 2)));

        if ($denominator == 0) {
            return 0.0;
        }

        return $numerator / $denominator;
    }
}
