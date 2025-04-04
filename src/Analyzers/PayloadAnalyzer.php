<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatcher;

final class PayloadAnalyzer extends AbstractAnalyzer
{
    /**
     * Configuration constants
     */
    private const CONFIG_ENABLED_KEY = 'citadel.payload.enable_payload_analyzer';

    private const CONFIG_CACHE_TTL_KEY = 'citadel.payload.cache_ttl';

    private const CONFIG_MAX_SCORE_KEY = 'citadel.payload.max_score';

    private const CONFIG_THREAT_THRESHOLD_KEY = 'citadel.payload.threat_threshold';

    /**
     * The multi-pattern matcher instance.
     */
    private MultiPatternMatcher $matcher;

    /**
     * Constructor.
     *
     * @param  DataStore  $dataStore  The datastore for caching.
     * @param  MultiPatternMatcher  $matcher  The preloaded matcher (injected).
     */
    public function __construct(DataStore $dataStore, MultiPatternMatcher $matcher)
    {
        parent::__construct($dataStore);
        $this->matcher = $matcher;

        // Set cache TTL from configuration
        $this->cacheTtl = config(self::CONFIG_CACHE_TTL_KEY, 3600);
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled(): bool
    {
        return (bool) config(self::CONFIG_ENABLED_KEY, true);
    }

    /**
     * {@inheritdoc}
     */
    public function requiresRequestBody(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function usesExternalResources(): bool
    {
        return false;
    }

    /**
     * Get a unique identifier for this analyzer.
     */
    public function getIdentifier(): string
    {
        return 'payload_analyzer';
    }

    /**
     * Analyze the HTTP request by scanning its content using the MultiPatternMatcher.
     *
     * @param  Request  $request  The incoming HTTP request.
     * @return float The computed impact score.
     */
    public function analyze(Request $request): float
    {
        // If analyzer is disabled, return 0 score
        if (! $this->isEnabled()) {
            return 0.0;
        }

        $content = $request->getContent();

        // Use a cache key based on the request fingerprint and content hash.
        $requestFingerprint = $request->getFingerprint();
        $cacheKey = $this->getIdentifier().':'.$requestFingerprint.':'.md5($content);

        if (($cached = $this->dataStore->getValue($cacheKey)) !== null) {
            Log::debug("PayloadAnalyzer cache hit for key: {$cacheKey}");

            return (float) $cached;
        }

        Log::info("PayloadAnalyzer starting scan for request with key: {$cacheKey}");

        // Perform the scan; get matches
        $matches = $this->matcher->scan($content);

        // Compute a score based on the number of matches
        $score = (float) count($matches);

        // Log matches for debugging
        foreach ($matches as $match) {
            Log::debug("PayloadAnalyzer matched pattern ID {$match->id}: '{$match->originalPattern}'");
        }

        // Cap the score at the configured maximum
        $maxScore = config(self::CONFIG_MAX_SCORE_KEY, 100.0);
        $score = min($score, $maxScore);

        Log::info('PayloadAnalyzer completed scan: found '.count($matches)." matches, final score = {$score}");

        // Cache the result.
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);

        return $score;
    }
}
