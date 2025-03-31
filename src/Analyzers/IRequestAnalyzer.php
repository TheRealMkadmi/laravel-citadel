<?php

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;

/**
 * Interface for all request analyzers in the Citadel system
 */
interface IRequestAnalyzer
{
    /**
     * Analyze the request and return a score indicating the threat level.
     * Higher scores indicate more suspicious/malicious behavior.
     */
    public function analyze(Request $request): float;

    /**
     * Check if this analyzer is enabled based on configuration.
     */
    public function isEnabled(): bool;

    /**
     * Check if this analyzer requires the request body for analysis.
     * If true, this analyzer will only run on requests that have a body.
     */
    public function requiresRequestBody(): bool;
    
    /**
     * Check if this analyzer makes external API calls or resource requests.
     * External resource analyzers can be globally disabled via environment config.
     */
    public function usesExternalResources(): bool;

    /**
     * Get a unique identifier for this analyzer type.
     * Used for cache keys and logging.
     */
    public function getIdentifier(): string;
}
