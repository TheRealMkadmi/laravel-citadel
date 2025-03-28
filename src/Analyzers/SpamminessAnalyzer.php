<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class SpamminessAnalyzer implements IRequestAnalyzer
{
    protected DataStore $dataStore;
    protected bool $enabled;
    protected array $weights;
    protected array $textAnalysisConfig;

    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
        $this->enabled = config('citadel.spamminess.enable_spamminess_analyzer', true);
        $this->weights = config('citadel.spamminess.weights', [
            'gibberish_text' => 25.0,
            'repetitive_content' => 10.0,
            'suspicious_entropy' => 20.0,
            'statistical_anomaly' => 30.0,
        ]);
        $this->textAnalysisConfig = config('citadel.spamminess.text_analysis', [
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
        if (!$this->enabled) {
            return 0.0;
        }

        $payload = $request->all();
        
        // Process all fields recursively, handling arrays and nested objects
        $score = $this->processPayload($payload);

        return min($score, config('citadel.spamminess.max_score', 100.0));
    }
    
    /**
     * Process payload data recursively, detecting anomalies in all values
     */
    protected function processPayload(mixed $data, string $prefix = ''): float
    {
        $score = 0.0;
        
        if (is_array($data) || is_object($data)) {
            $data = Arr::wrap($data);
            
            foreach ($data as $key => $value) {
                $currentPath = $prefix ? "{$prefix}.{$key}" : $key;
                $score += $this->processPayload($value, $currentPath);
            }
        } elseif (is_string($data)) {
            $score += $this->analyzeTextField($data);
        }
        
        return $score;
    }

    protected function analyzeTextField(string $text): float
    {
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
        foreach (preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY) as $ch) {
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
        foreach (preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY) as $char) {
            if ($char === $lastChar) {
                $repeats++;
            }
            $lastChar = $char;
        }

        $repetitionRatio = $repeats / $len;
        
        // Check for word repetition patterns
        $words = Str::of($text)->explode(' ')->filter()->values()->toArray();
        $wordCount = count($words);
        
        if ($wordCount > 1) {
            $uniqueWords = count(array_unique($words));
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
        
        // 3. Character distribution analysis
        $scores[] = $this->characterDistributionScore($textLower);
        
        // 4. Statistical n-gram analysis
        $scores[] = $this->statisticalNgramAnalysis($textLower);
        
        // 5. Zipf's law deviation analysis
        $scores[] = $this->zipfLawDeviationAnalysis($textLower);
        
        // Weight and normalize scores
        $validScores = array_filter($scores, function($score) {
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
        
        foreach (preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY) as $char) {
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
        
        // Calculate statistical measures on character distribution
        $charDistribution = [];
        foreach ($charCount as $char => $count) {
            $charDistribution[$char] = $count / $totalChars;
        }
        
        // Calculate standard deviation of distribution
        $values = array_values($charDistribution);
        $mean = array_sum($values) / count($values);
        $variance = 0;
        
        foreach ($values as $value) {
            $variance += pow($value - $mean, 2);
        }
        
        $stdDev = sqrt($variance / count($values));
        
        // Calculate coefficient of variation (measure of relative variability)
        $cv = $stdDev / $mean;
        
        // Normalize to 0-1 score
        $threshold = $this->textAnalysisConfig['character_distribution_threshold'];
        $normalizedScore = min(1.0, $cv / $threshold);
        
        return $normalizedScore;
    }
    
    /**
     * Get character frequencies from text
     * @return array<string, int>
     */
    protected function getCharacterFrequencies(string $text): array
    {
        $freq = [];
        foreach (preg_split('//u', Str::lower($text), -1, PREG_SPLIT_NO_EMPTY) as $ch) {
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
            $expectedZipf[$rank-1] = $firstFreq / $rank;
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
        
        $sumXSq = array_sum(array_map(function($val) { 
            return pow($val, 2); 
        }, $x));
        
        $sumYSq = array_sum(array_map(function($val) { 
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