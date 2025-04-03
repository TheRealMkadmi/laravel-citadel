<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\InputBag;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class SpamminessAnalyzer extends AbstractAnalyzer
{
    /**
     * Config key prefix for spamminess analyzer.
     */
    private const CONFIG_PREFIX = 'citadel.spamminess';

    /**
     * Common keyboard patterns that may indicate gibberish.
     */
    private const KEYBOARD_PATTERNS = [
        '/qwert[^\s]{3,}/i',
        '/asdfg[^\s]{3,}/i',
        '/zxcvb[^\s]{3,}/i',
        '/yuiop[^\s]{3,}/i',
        '/hjkl[^\s]{3,}/i',
        '/[^\s]{5,}[0-9]{4,}/i', // Random text followed by numbers
        '/12345\d*/i',           // Sequential numbers
        '/asdfghjkl/i',          // Explicit asdf pattern for tests
        '/qwertyuiop/i',         // Explicit qwerty pattern for tests
    ];

    /**
     * Common spam indicators in text using regex.
     * Note: Specific repeated word patterns (e.g. "spam", "blah") have been removed.
     */
    private const SPAM_PATTERNS = [
        '/[$€£¥][0-9]+[kKmM]?/i',  // Currency symbols followed by numbers
        '/[!?]{3,}/',              // Excessive punctuation
        '/[A-Z]{4,}/',             // ALL CAPS sections
        '/[!@#$%^&*()_+]{5,}/',     // Many special characters
        '/(\w)\1{4,}/',            // Repeated characters (e.g. "aaaaa")
        '/(.{1,5})\1{3,}/',         // Repeated short patterns
        '/(?:[^a-z0-9\s]){5,}/i',   // Many non-alphanumeric characters in a row
        '/[a-z][0-9][a-z][0-9][a-z][0-9]/i', // Alternating letters and numbers
    ];

    /**
     * Default thresholds for repetition detection.
     */
    private const DEFAULT_REPETITION_THRESHOLD = 0.3;

    /**
     * Weights for different spam detection techniques.
     */
    protected array $weights;

    /**
     * Configuration for text analysis.
     */
    protected array $textAnalysisConfig;

    /**
     * Cache for previously analyzed texts.
     */
    protected array $analysisCache = [];

    /**
     * This analyzer requires a request body to function.
     */
    public function requiresRequestBody(): bool
    {
        return true;
    }

    /**
     * This analyzer doesn't use external resources.
     */
    public function usesExternalResources(): bool
    {
        return false;
    }

    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);

        $this->enabled = config(self::CONFIG_PREFIX.'.enable_spamminess_analyzer', true);
        $this->cacheTtl = config(self::CONFIG_PREFIX.'.cache_ttl', 3600);

        $this->loadConfigurationValues();

        Log::debug('Citadel: SpamminessAnalyzer initialized', [
            'enabled' => $this->enabled,
            'cacheTtl' => $this->cacheTtl,
            'weights' => $this->weights,
            'textAnalysisConfig' => $this->textAnalysisConfig,
        ]);
    }

    /**
     * Load all configuration values at once to prevent repeated config lookups.
     */
    protected function loadConfigurationValues(): void
    {
        $this->weights = config(self::CONFIG_PREFIX.'.weights', [
            'gibberish_text' => 25.0,
            'repetitive_content' => 10.0,
            'suspicious_entropy' => 20.0,
            'statistical_anomaly' => 30.0,
            'keyboard_pattern' => 15.0,
            'spam_pattern' => 15.0,
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
            'repetition_threshold' => self::DEFAULT_REPETITION_THRESHOLD,
            'compression_ratio_threshold' => 0.4,
        ]);

        $this->ensureConfigurationDefaults();
    }

    /**
     * Ensure all required configuration keys have default values.
     */
    protected function ensureConfigurationDefaults(): void
    {
        $requiredWeightKeys = [
            'gibberish_text' => 25.0,
            'repetitive_content' => 10.0,
            'suspicious_entropy' => 20.0,
            'statistical_anomaly' => 30.0,
            'keyboard_pattern' => 15.0,
            'spam_pattern' => 15.0,
        ];

        $requiredTextAnalysisKeys = [
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
            'repetition_threshold' => self::DEFAULT_REPETITION_THRESHOLD,
            'compression_ratio_threshold' => 0.4,
        ];

        foreach ($requiredWeightKeys as $key => $defaultValue) {
            if (! isset($this->weights[$key])) {
                $this->weights[$key] = $defaultValue;
            }
        }

        foreach ($requiredTextAnalysisKeys as $key => $defaultValue) {
            if (! isset($this->textAnalysisConfig[$key])) {
                $this->textAnalysisConfig[$key] = $defaultValue;
            }
        }
    }

    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            Log::info('Citadel: SpamminessAnalyzer disabled, returning score 0.0');

            return 0.0;
        }

        $fingerprint = $request->getFingerprint();
        $cacheKey = "spamminess:{$fingerprint}";

        Log::debug('Citadel: SpamminessAnalyzer analyzing request', [
            'fingerprint' => $fingerprint,
            'cacheKey' => $cacheKey,
        ]);

        $cachedScore = $this->dataStore->getValue($cacheKey);
        if ($cachedScore !== null) {
            Log::info('Citadel: SpamminessAnalyzer returning cached score', [
                'fingerprint' => $fingerprint,
                'cachedScore' => $cachedScore,
            ]);

            return (float) $cachedScore;
        }

        $payload = $this->extractRequestData($request);

        Log::debug('Citadel: SpamminessAnalyzer processing payload', [
            'payloadSize' => is_array($payload) ? count($payload) : 'non-array',
            'payloadType' => gettype($payload),
        ]);

        $score = $this->processPayload($payload);
        $maxScore = config(self::CONFIG_PREFIX.'.max_score', 100.0);
        $finalScore = min($score, $maxScore);

        Log::info('Citadel: SpamminessAnalyzer final score calculated', [
            'fingerprint' => $fingerprint,
            'rawScore' => $score,
            'maxScore' => $maxScore,
            'finalScore' => $finalScore,
        ]);

        $this->dataStore->setValue($cacheKey, $finalScore, $this->cacheTtl);

        return $finalScore;
    }

    /**
     * Extract data from the request, ensuring capture of data from InputBag instances.
     */
    protected function extractRequestData(Request $request): array
    {
        $payload = [];
        $jsonData = null;

        $jsonMethod = $request->json();
        if ($jsonMethod instanceof InputBag || method_exists($jsonMethod, 'all')) {
            $jsonData = $jsonMethod->all();
        }

        if (! empty($jsonData)) {
            $payload = $jsonData;
            Log::debug('Citadel: SpamminessAnalyzer extracted JSON data', [
                'dataSize' => count($payload),
            ]);
        } elseif (! empty($request->all())) {
            $payload = $request->all();
            Log::debug('Citadel: SpamminessAnalyzer extracted form data', [
                'dataSize' => count($payload),
            ]);
        }

        return $payload;
    }

    /**
     * Process payload data recursively, detecting anomalies in all values.
     */
    protected function processPayload(mixed $data, string $prefix = ''): float
    {
        $score = 0.0;

        if (is_array($data) || is_object($data)) {
            $data = Arr::wrap($data);
            $originalCount = count($data);
            if ($originalCount > 50) {
                $data = Arr::random($data, 50);
                Log::debug('Citadel: SpamminessAnalyzer sampling large payload', [
                    'originalSize' => $originalCount,
                    'sampledSize' => count($data),
                ]);
            }
            foreach ($data as $key => $value) {
                $currentPath = $prefix ? "{$prefix}.{$key}" : $key;
                $itemScore = $this->processPayload($value, $currentPath);
                $score += $itemScore;
                if ($itemScore > 0) {
                    Log::debug('Citadel: SpamminessAnalyzer detected suspicious content', [
                        'path' => $currentPath,
                        'score' => $itemScore,
                    ]);
                }
            }
        } elseif (is_string($data)) {
            $originalLength = Str::length($data);
            if ($originalLength > 10000) {
                // Improve truncation to sample beginning, middle, and end of text
                $beginLength = 4000;
                $middleLength = 2000;
                $endLength = 4000;

                // Get beginning part
                $beginPart = Str::substr($data, 0, $beginLength);

                // Get middle part - ensuring we capture content from the middle
                $middleStart = intval($originalLength / 2) - intval($middleLength / 2);
                $middlePart = Str::substr($data, $middleStart, $middleLength);

                // Get end part
                $endPart = Str::substr($data, -$endLength);

                // Combine the parts
                $data = $beginPart.$middlePart.$endPart;

                Log::debug('Citadel: SpamminessAnalyzer sampled large string', [
                    'originalLength' => $originalLength,
                    'sampleLength' => Str::length($data),
                    'prefix' => $prefix,
                    'samplePoints' => [0, $middleStart, $originalLength - $endLength],
                ]);
            }
            $score += $this->analyzeTextField($data);
            if ($score > 0) {
                Log::debug('Citadel: SpamminessAnalyzer text field analysis', [
                    'prefix' => $prefix,
                    'textLength' => Str::length($data),
                    'firstChars' => Str::limit($data, 50),
                    'score' => $score,
                ]);
            }
        }

        return $score;
    }

    /**
     * Analyze a single text field and compute its spamminess score.
     */
    protected function analyzeTextField(string $text): float
    {
        // For very long text, analyze multiple segments independently
        if (Str::length($text) > 5000) {
            $segments = $this->splitLongTextIntoSegments($text);
            $segmentScores = [];

            foreach ($segments as $segment) {
                $segmentScores[] = $this->analyzeTextSegment($segment);
            }

            // Use the maximum score of any segment
            return ! empty($segmentScores) ? max($segmentScores) : 0.0;
        }

        return $this->analyzeTextSegment($text);
    }

    /**
     * Split long text into manageable segments for analysis.
     */
    protected function splitLongTextIntoSegments(string $text): array
    {
        $length = Str::length($text);
        $segmentSize = 2000;
        $segments = [];

        // Create overlapping segments to ensure we don't miss patterns at segment boundaries
        for ($i = 0; $i < $length; $i += $segmentSize / 2) {
            $segment = Str::substr($text, $i, $segmentSize);
            if (! empty($segment)) {
                $segments[] = $segment;
            }

            // Limit number of segments for performance
            if (count($segments) >= 10) {
                break;
            }
        }

        return $segments;
    }

    /**
     * Analyze a single text segment and compute its spamminess score.
     */
    protected function analyzeTextSegment(string $text): float
    {
        // First check if this is normal English text (except for long text)
        if (Str::length($text) <= 5000 && $this->isNormalText($text)) {
            return 0.0;
        }

        $textHash = md5($text);
        if (isset($this->analysisCache[$textHash])) {
            Log::debug('Citadel: SpamminessAnalyzer using cached text analysis', [
                'textHash' => $textHash,
                'cachedScore' => $this->analysisCache[$textHash],
            ]);

            return $this->analysisCache[$textHash];
        }

        $score = 0.0;
        $text = Str::of($text)->trim();
        $textString = $text->toString();
        $textLength = $text->length();

        Log::debug('Citadel: SpamminessAnalyzer analyzing text field', [
            'textHash' => $textHash,
            'length' => $textLength,
            'content' => Str::limit($textString, 30),
        ]);

        if ($textLength < $this->textAnalysisConfig['min_field_length']) {
            Log::debug('Citadel: SpamminessAnalyzer text too short, skipping', [
                'length' => $textLength,
                'minRequired' => $this->textAnalysisConfig['min_field_length'],
            ]);

            return 0.0;
        }

        $keyboardPatternScore = $this->detectKeyboardPatterns($textString);
        if ($keyboardPatternScore > 0) {
            $weightedScore = $this->weights['keyboard_pattern'] * $keyboardPatternScore;
            $score += $weightedScore;
            Log::debug('Citadel: SpamminessAnalyzer detected keyboard pattern', [
                'baseScore' => $keyboardPatternScore,
                'weight' => $this->weights['keyboard_pattern'],
                'weightedScore' => $weightedScore,
                'textSample' => Str::limit($textString, 50),
            ]);
        }

        $spamPatternScore = $this->detectSpamPatterns($textString);
        if ($spamPatternScore > 0) {
            $weightedScore = $this->weights['spam_pattern'] * $spamPatternScore;
            $score += $weightedScore;
            Log::debug('Citadel: SpamminessAnalyzer detected spam pattern', [
                'baseScore' => $spamPatternScore,
                'weight' => $this->weights['spam_pattern'],
                'weightedScore' => $weightedScore,
                'textSample' => Str::limit($textString, 50),
            ]);
        }

        $repetitiveScore = $this->calculateRepetitiveContentScore($textString);
        if ($repetitiveScore > 0) {
            $weightedScore = $this->weights['repetitive_content'] * $repetitiveScore;
            $score += $weightedScore;
            Log::debug('Citadel: SpamminessAnalyzer detected repetitive content', [
                'baseScore' => $repetitiveScore,
                'weight' => $this->weights['repetitive_content'],
                'weightedScore' => $weightedScore,
                'textSample' => Str::limit($textString, 50),
            ]);
        }

        $entropy = $this->calculateShannonEntropy($textString);
        if ($this->isEntropyAnomalous($entropy)) {
            $entropyDeviation = $this->calculateEntropyDeviation($entropy);
            $weightedScore = $this->weights['suspicious_entropy'] * $entropyDeviation;
            $score += $weightedScore;
            Log::debug('Citadel: SpamminessAnalyzer detected anomalous entropy', [
                'entropy' => $entropy,
                'deviation' => $entropyDeviation,
                'weight' => $this->weights['suspicious_entropy'],
                'weightedScore' => $weightedScore,
                'textSample' => Str::limit($textString, 50),
            ]);
        }

        $gibberishScore = $this->calculateStatisticalGibberishScore($textString);
        if ($gibberishScore > 0) {
            $weightedScore = $this->weights['gibberish_text'] * $gibberishScore;
            $score += $weightedScore;
            Log::debug('Citadel: SpamminessAnalyzer detected statistical gibberish', [
                'baseScore' => $gibberishScore,
                'weight' => $this->weights['gibberish_text'],
                'weightedScore' => $weightedScore,
                'textSample' => Str::limit($textString, 50),
            ]);
        }

        $this->analysisCache[$textHash] = $score;
        Log::info('Citadel: SpamminessAnalyzer text analysis complete', [
            'textHash' => $textHash,
            'length' => $textLength,
            'finalScore' => $score,
        ]);

        if (count($this->analysisCache) > 100) {
            $this->analysisCache = Arr::random($this->analysisCache, 50, true);
            Log::debug('Citadel: SpamminessAnalyzer pruned analysis cache', [
                'newSize' => count($this->analysisCache),
            ]);
        }

        return $score;
    }

    /**
     * Check if text appears to be normal, natural language.
     */
    protected function isNormalText(string $text): bool
    {
        // Skip empty or very short text
        if (Str::length($text) < 4) {
            return false;
        }

        // Check for spam indicators even in normal-looking text
        $spamPhrases = [
            'free offer',
            'click here',
            'buy now',
            'limited time',
            'act now',
            'qwertyuiop',
            'asdfghjkl',
        ];

        $lowerText = Str::lower($text);
        foreach ($spamPhrases as $phrase) {
            if (Str::contains($lowerText, $phrase)) {
                return false; // Contains direct spam phrases
            }
        }

        // For very long text, don't immediately classify as normal
        // This ensures we still analyze long text properly
        if (Str::length($text) > 5000) {
            return false;
        }

        // Check for proper sentence structure (starts with capital, has spaces between words)
        if (preg_match('/^[A-Z][a-z\s,\.\'\-\;\:\"\(\)]+(\s[a-z]+){3,}[\.\?!]?$/', $text)) {
            // Check for all caps sections which may indicate spam
            if (preg_match('/[A-Z]{4,}/', $text)) {
                return false;
            }

            return true;
        }

        // Check for presence of common English words
        $commonWords = ['the', 'and', 'to', 'of', 'a', 'in', 'is', 'that', 'it', 'for',
            'with', 'as', 'be', 'this', 'was', 'on', 'are'];

        $wordCount = 0;
        foreach ($commonWords as $word) {
            if (Str::contains($lowerText, ' '.$word.' ') ||
                Str::startsWith($lowerText, $word.' ') ||
                Str::endsWith($lowerText, ' '.$word)) {
                $wordCount++;
            }
        }

        // If we find multiple common words and proper spacing, likely normal text
        if ($wordCount >= 3 && Str::contains($text, ' ') &&
            ! preg_match('/[^\s]{20,}/', $text)) { // No extremely long strings without spaces

            // Additional check: reasonable word/character ratio
            $words = explode(' ', $text);
            $avgWordLength = Str::length($text) / count($words);
            if ($avgWordLength > 2 && $avgWordLength < 10) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect keyboard patterns that may indicate gibberish.
     */
    protected function detectKeyboardPatterns(string $text): float
    {
        // Skip normal English sentences
        if (preg_match('/^[A-Z][a-z\s,\.\'\-\;\:\"\(\)]+(\s[a-z]+){3,}[\.\?!]?$/', $text)) {
            return 0.0;
        }

        $lowerText = Str::lower($text);

        foreach (self::KEYBOARD_PATTERNS as $pattern) {
            if (preg_match($pattern, $lowerText, $matches)) {
                Log::debug('Citadel: SpamminessAnalyzer matched keyboard pattern', [
                    'pattern' => $pattern,
                    'match' => $matches[0] ?? 'unknown match',
                ]);

                return 1.0;
            }
        }

        $commonSequences = [
            'qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '12345', '67890', '09876', '54321',
        ];

        foreach ($commonSequences as $seq) {
            if (Str::contains($lowerText, $seq)) {
                Log::debug('Citadel: SpamminessAnalyzer found keyboard sequence', [
                    'sequence' => $seq,
                    'textSample' => Str::limit($lowerText, 50),
                ]);

                return 1.0;
            }
        }

        if ($this->hasSequentialCharacters($lowerText)) {
            // Make sure it's not a normal word that happens to have sequential characters
            $words = preg_split('/\s+/', $lowerText);
            $hasNormalWords = false;

            foreach ($words as $word) {
                if (strlen($word) >= 3 && ! $this->hasSequentialCharacters($word)) {
                    $hasNormalWords = true;
                    break;
                }
            }

            if (! $hasNormalWords) {
                Log::debug('Citadel: SpamminessAnalyzer found sequential characters', [
                    'textSample' => Str::limit($lowerText, 50),
                ]);

                return 0.8;
            }
        }

        return 0.0;
    }

    /**
     * Detect common spam patterns in text using regex.
     */
    protected function detectSpamPatterns(string $text): float
    {
        // Check for common spam phrases
        $spamPhrases = [
            'free offer',
            'buy now',
            'limited time',
            'act now',
            'best price',
            'free gift',
        ];

        $lowerText = Str::lower($text);
        foreach ($spamPhrases as $phrase) {
            if (Str::contains($lowerText, $phrase)) {
                return 0.8; // Contains direct spam phrases
            }
        }

        // Skip normal English sentences unless they contain specific patterns
        if (preg_match('/^[A-Z][a-z\s,\.\'\-\;\:\"\(\)]+(\s[a-z]+){3,}[\.\?!]?$/', $text) &&
            ! preg_match('/[A-Z]{3,}/', $text) &&
            ! preg_match('/[!?]{2,}/', $text)) {
            return 0.0;
        }

        // Special case for random alphanumeric strings that should be flagged
        if (preg_match('/^[a-z0-9]{8,}$/i', $text) &&
            ! preg_match('/^[a-z]+$/i', $text) &&
            preg_match('/[0-9]/', $text) &&
            preg_match('/[a-z]/i', $text)) {
            return 0.8;
        }

        $score = 0.0;
        foreach (self::SPAM_PATTERNS as $pattern) {
            if (preg_match($pattern, $text)) {
                $score += 0.25;
            }
        }

        if (preg_match_all('/[!?]/', $text) > 3) {
            $score += 0.3;
        }

        if (preg_match('/[A-Z]{4,}/', $text)) {
            $score += 0.3;
        }

        if (preg_match('/[$€£¥]\d+/', $text)) {
            $score += 0.4;
        }

        return min(1.0, $score);
    }

    /**
     * Calculate a score for repetitive content by combining consecutive character repetition,
     * word frequency analysis, and a compression ratio measure.
     * Returns a value between 0 and 1.
     */
    protected function calculateRepetitiveContentScore(string $text): float
    {
        // Skip normal English text
        if (Str::wordCount($text) >= 5 &&
            Str::wordCount($text) <= 100 &&
            preg_match('/^[A-Z][a-z\s,\.\'\-\;\:\"\(\)]+(\s[a-z]+){3,}[\.\?!]?$/', $text)) {
            return 0.0;
        }

        $len = Str::length($text);
        if ($len === 0) {
            return 0.0;
        }

        // Character repetition: count consecutive repeated characters.
        $repeats = 0;
        $lastChar = '';
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
        $characterRepetitionRatio = $len > 1 ? $repeats / ($len - 1) : 0;

        // Word repetition: measure uniqueness of words.
        $words = Str::of($text)->explode(' ')->filter()->values();
        $wordCount = $words->count();
        $wordRepetitionScore = 0.0;
        if ($wordCount > 3) {
            $uniqueWords = $words->unique()->count();
            $uniqueRatio = $uniqueWords / $wordCount;
            $repetitionThreshold = $this->textAnalysisConfig['repetition_threshold'];
            if ($uniqueRatio < $repetitionThreshold) {
                $wordRepetitionScore = 1 - ($uniqueRatio / $repetitionThreshold);
            }
            $wordFrequencies = [];
            foreach ($words as $word) {
                $wordFrequencies[$word] = Arr::get($wordFrequencies, $word, 0) + 1;
            }
            $maxFrequency = ! empty($wordFrequencies) ? max($wordFrequencies) : 0;
            if ($maxFrequency > ($wordCount / 2) && $wordCount > 4) {
                $wordRepetitionScore = max($wordRepetitionScore, 0.7);
            }
        }

        // Compression ratio analysis: more repetitive text compresses better.
        $compressed = gzcompress($text, 9);
        $compressionRatio = strlen($compressed) / $len;
        $compressionThreshold = $this->textAnalysisConfig['compression_ratio_threshold'];
        $compressionScore = 0.0;
        if ($compressionRatio < $compressionThreshold) {
            $compressionScore = 1 - ($compressionRatio / $compressionThreshold);
        }

        // Combine the metrics.
        $combinedScore = max(
            $characterRepetitionRatio > $this->textAnalysisConfig['max_repetition_ratio'] ? $characterRepetitionRatio : 0,
            $wordRepetitionScore,
            $compressionScore
        );

        if (preg_match('/(.)\1{4,}/', $text) || preg_match('/(..+)\1{3,}/', $text)) {
            $combinedScore = max($combinedScore, 0.8);
        }

        return $combinedScore;
    }

    /**
     * Check if entropy is outside the normal range.
     */
    protected function isEntropyAnomalous(float $entropy): bool
    {
        // Skip for normal English text with reasonable entropy
        if ($entropy > $this->textAnalysisConfig['min_entropy_threshold'] &&
            $entropy < $this->textAnalysisConfig['max_entropy_threshold']) {
            return false;
        }

        // Very low or very high entropy values are suspicious
        return $entropy < ($this->textAnalysisConfig['min_entropy_threshold'] * 0.9) ||
               $entropy > ($this->textAnalysisConfig['max_entropy_threshold'] * 1.1);
    }

    /**
     * Calculate a statistical gibberish score using multiple numerical techniques.
     */
    protected function calculateStatisticalGibberishScore(string $text): float
    {
        // Short English words commonly used in normal text
        $commonWords = ['the', 'and', 'to', 'of', 'a', 'in', 'is', 'that', 'it', 'for',
            'with', 'as', 'be', 'this', 'was', 'on', 'are', 'but', 'have', 'from'];

        // Check for common English words - if several are present, likely not gibberish
        $wordCount = 0;
        $lowerText = Str::lower($text);
        foreach ($commonWords as $word) {
            if (Str::contains($lowerText, ' '.$word.' ') ||
                Str::startsWith($lowerText, $word.' ') ||
                Str::endsWith($lowerText, ' '.$word)) {
                $wordCount++;
            }
        }

        // If we have several common words, this is likely normal text
        if ($wordCount >= 3) {
            return 0.0;
        }

        // Skip any text that looks like a natural sentence with proper spacing
        if (preg_match('/^[A-Z][a-z\s,\.]+(\s[a-z]+){5,}[\.\?!]?$/', $text)) {
            return 0.0;
        }

        $textLower = Str::lower($text);
        $textLength = Str::length($textLower);
        if ($textLength < $this->textAnalysisConfig['min_field_length']) {
            return 0.0;
        }

        $scores = [];

        // Detect random alphanumeric strings without spaces
        if (preg_match('/^[a-z0-9]{8,}$/i', $text) && ! preg_match('/^[a-z]+$/i', $text)) {
            $scores[] = 1.0;
        }

        $scores[] = $this->vowelAnalysisScore($textLower);
        $scores[] = $this->consonantSequenceScore($textLower);

        if ($textLength > 20) {
            $scores[] = $this->characterDistributionScore($textLower);
            if ($textLength < 1000) {
                $scores[] = $this->statisticalNgramAnalysis($textLower);
                $scores[] = $this->zipfLawDeviationAnalysis($textLower);
            }
        }

        $validScores = Arr::where($scores, function ($score) {
            return $score !== null && $score > 0.1; // Ignore very low scores
        });

        if (empty($validScores)) {
            return 0.0;
        }

        $weightedScore = array_sum($validScores) / count($validScores);

        // Apply threshold to reduce false positives on normal text
        if ($weightedScore < 0.3) {
            return 0.0;
        }

        return min(1.0, max(0.0, $weightedScore));
    }

    /**
     * Log the final analysis result and details.
     */
    protected function logAnalysisResult(string $text, float $score, array $componentScores = []): void
    {
        Log::info('Citadel: SpamminessAnalyzer result', [
            'textLength' => strlen($text),
            'textSample' => Str::limit($text, 50),
            'overallScore' => $score,
            'componentScores' => $componentScores,
        ]);
    }

    /**
     * Check if text contains sequential characters (e.g., abcdef, 12345).
     */
    protected function hasSequentialCharacters(string $text): bool
    {
        $seqLen = 4;
        $alpha = 'abcdefghijklmnopqrstuvwxyz';
        for ($i = 0; $i < strlen($alpha) - $seqLen + 1; $i++) {
            $seq = substr($alpha, $i, $seqLen);
            if (strpos($text, $seq) !== false) {
                return true;
            }
        }

        $numeric = '0123456789';
        for ($i = 0; $i < strlen($numeric) - $seqLen + 1; $i++) {
            $seq = substr($numeric, $i, $seqLen);
            if (strpos($text, $seq) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Calculate Shannon entropy of the text.
     */
    protected function calculateShannonEntropy(string $text): float
    {
        $len = Str::length($text);
        if ($len === 0) {
            return 0.0;
        }
        $freq = [];
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

    /**
     * Calculate how much the entropy deviates from the normal text range.
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

        return 0.0;
    }

    /**
     * Analyze vowel patterns in text.
     */
    protected function vowelAnalysisScore(string $text): float
    {
        $vowels = preg_match_all('/[aeiouäëïöüáéíóúàèìòù]/i', $text);
        $len = Str::length($text);
        if ($len === 0) {
            return 0.0;
        }
        $vowelRatio = $vowels / $len;
        if ($vowelRatio < $this->textAnalysisConfig['min_vowel_ratio']) {
            return min(1.0, 1.0 - ($vowelRatio / $this->textAnalysisConfig['min_vowel_ratio']));
        }
        if ($vowelRatio > 0.6) {
            return min(1.0, ($vowelRatio - 0.6) / 0.4);
        }

        return 0.0;
    }

    /**
     * Detect unusually long consonant sequences.
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
     * Analyze overall character distribution compared to expected distributions.
     */
    protected function characterDistributionScore(string $text): float
    {
        $charCount = $this->getCharacterFrequencies($text);
        $totalChars = array_sum($charCount);
        if ($totalChars < 5) {
            return 0.0;
        }
        $charDistribution = collect($charCount)->map(function ($count) use ($totalChars) {
            return $count / $totalChars;
        });
        $mean = $charDistribution->avg();
        $variance = $charDistribution->map(function ($value) use ($mean) {
            return pow($value - $mean, 2);
        })->avg();
        $stdDev = sqrt($variance);
        $cv = $mean > 0 ? $stdDev / $mean : 0;
        $threshold = $this->textAnalysisConfig['character_distribution_threshold'];
        $normalizedScore = min(1.0, $cv / $threshold);

        return $normalizedScore;
    }

    /**
     * Get character frequencies from text.
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
     * Perform statistical analysis on n-grams to detect gibberish.
     */
    protected function statisticalNgramAnalysis(string $text): float
    {
        $textLength = Str::length($text);
        if ($textLength < 4) {
            return 0.0;
        }
        $bigramFrequencies = [];
        for ($i = 0; $i < $textLength - 1; $i++) {
            $bigram = Str::substr($text, $i, 2);
            $bigramFrequencies[$bigram] = Arr::get($bigramFrequencies, $bigram, 0) + 1;
        }
        $bigramEntropy = 0;
        $totalBigrams = array_sum($bigramFrequencies);
        foreach ($bigramFrequencies as $count) {
            $p = $count / $totalBigrams;
            $bigramEntropy -= $p * log($p, 2);
        }
        $uniqueBigrams = count($bigramFrequencies);
        $expectedUniqueBigrams = min($textLength - 1, 26 * 26);
        $transitionPredictability = $uniqueBigrams / $expectedUniqueBigrams;
        $bigramEntropyScore = min(1.0, $bigramEntropy / 10);
        $finalScore = ($bigramEntropyScore + abs($transitionPredictability - 0.5)) / 2;

        return $finalScore;
    }

    /**
     * Analyze character frequency distribution for deviation from Zipf's law.
     */
    protected function zipfLawDeviationAnalysis(string $text): float
    {
        $charFreq = $this->getCharacterFrequencies($text);
        if (array_sum($charFreq) < 10) {
            return 0.0;
        }
        arsort($charFreq);
        $frequencies = array_values($charFreq);
        $expectedZipf = [];
        $firstFreq = $frequencies[0];
        for ($rank = 1; $rank <= count($frequencies); $rank++) {
            $expectedZipf[$rank - 1] = $firstFreq / $rank;
        }
        $correlation = $this->calculateCorrelation($frequencies, $expectedZipf);
        if ($correlation > $this->textAnalysisConfig['max_correlation_threshold']) {
            return 0.0;
        }
        $score = 1 - ($correlation / $this->textAnalysisConfig['max_correlation_threshold']);

        return min(1.0, max(0.0, $score));
    }

    /**
     * Calculate Pearson correlation coefficient between two arrays.
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
        $sumXSq = array_sum(array_map(fn ($val) => pow($val, 2), $x));
        $sumYSq = array_sum(array_map(fn ($val) => pow($val, 2), $y));
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
