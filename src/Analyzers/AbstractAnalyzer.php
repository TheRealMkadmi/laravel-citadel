<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\AnalyzerType;

abstract class AbstractAnalyzer implements IRequestAnalyzer
{
    /**
     * The data store for caching results.
     */
    protected DataStore $dataStore;

    /**
     * Flag to enable or disable the analyzer.
     */
    protected bool $enabled = true;

    /**
     * Whether this takes active action against the request or the client to decide
     */
    protected AnalyzerType $analyzerType = AnalyzerType::PASSIVE;

    /**
     * Cache TTL in seconds.
     */
    protected int $cacheTtl = 3600;

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
    }

    /**
     * Check if this analyzer is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Check if this analyzer scans payload content.
     */
    public function scansPayload(): bool
    {
        // Scans payload is determined by the analyzer implementation
        // Override in specific analyzers as needed
        return false;
    }

    /**
     * Check if this analyzer is active (blocks requests) or passive (only monitors).
     */
    public function isActive(): bool
    {
        return $this->analyzerType === AnalyzerType::ACTIVE || $this->analyzerType === AnalyzerType::BOTH;
    }

    /**
     * Get the analyzer type enum value.
     */
    public function getAnalyzerType(): AnalyzerType
    {
        return $this->analyzerType;
    }

    /**
     * Analyze the request.
     */
    abstract public function analyze(Request $request): float;
}
