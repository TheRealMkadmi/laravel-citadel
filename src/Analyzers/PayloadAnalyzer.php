<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers\MultiPatternMatcher;

final class PayloadAnalyzer extends AbstractAnalyzer
{
    /**
     * The multi-pattern matcher instance (using libvectorscan).
     *
     * @var MultiPatternMatcher
     */
    private MultiPatternMatcher $matcher;

    /**
     * Optionally, a mapping from pattern id to an impact value.
     *
     * @var array<int, float>
     */
    private array $patternImpacts;

    /**
     * Constructor.
     *
     * @param DataStore            $dataStore       The datastore for caching.
     * @param MultiPatternMatcher  $matcher         The preloaded matcher (injected).
     * @param array<int, float>    $patternImpacts  Optional mapping of pattern IDs to impact scores.
     */
    public function __construct(DataStore $dataStore, MultiPatternMatcher $matcher, array $patternImpacts = [])
    {
        parent::__construct($dataStore);
        $this->matcher = $matcher;
        // If no mapping is provided, default each pattern to an impact of 1.
        $this->patternImpacts = $patternImpacts ?: array_fill(0, count($matcher->getPatterns()), 1.0);
    }

    /**
     * Analyze the HTTP request by scanning its content using the MultiPatternMatcher.
     *
     * The analyzer logs the start and result of scanning.
     * It computes a float score as the sum of impacts of all matched rules.
     *
     * @param Request $request The incoming HTTP request.
     * @return float The computed impact score.
     */
    public function analyze(Request $request): float
    {
        $content = $request->getContent();

        // Use a cache key based on the request content hash.
        $cacheKey = $this->getIdentifier() . ':' . md5($content);
        if (($cached = $this->dataStore->getValue($cacheKey)) !== null) {
            Log::debug("VectorscanAnalyzer cache hit for key: {$cacheKey}");
            return (float)$cached;
        }

        Log::info("VectorscanAnalyzer starting scan for request with key: {$cacheKey}");
        
        // Perform the scan; get a collection of match objects.
        $matches = $this->matcher->scan($content);
        
        // Compute a score. For this example, we sum the impact values of each match.
        $score = 0.0;
        foreach ($matches as $match) {
            // Ensure pattern impact mapping exists.
            $impact = $this->patternImpacts[$match->id] ?? 1.0;
            $score += $impact;
        }

        Log::info("VectorscanAnalyzer completed scan: found " . count($matches) . " matches, score = {$score}");

        // Cache the result.
        $this->dataStore->setValue($cacheKey, $score, $this->cacheTtl);
        
        return $score;
    }
}
