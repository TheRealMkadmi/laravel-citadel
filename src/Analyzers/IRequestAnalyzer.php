<?php

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use TheRealMkadmi\Citadel\Enums\AnalyzerType;

interface IRequestAnalyzer
{
    /**
     * Analyze the request and return a score indicating the threat level.
     */
    public function analyze(Request $request): float;

    /**
     * Check if this analyzer is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Check if this analyzer scans payload content.
     */
    public function scansPayload(): bool;
    
    /**
     * Check if this analyzer invokes external resources.
     */
    public function invokesExternalResource(): bool;

    /**
     * Check if this analyzer is active (blocks requests) or passive (only monitors).
     */
    public function isActive(): bool;
    
    /**
     * Get the analyzer type enum value.
     */
    public function getAnalyzerType(): AnalyzerType;
}
