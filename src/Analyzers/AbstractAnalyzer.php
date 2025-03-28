<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use TheRealMkadmi\Citadel\DataStore\DataStore;

abstract class AbstractAnalyzer implements IRequestAnalyzer
{
    /**
     * The data store for caching results.
     */
    protected DataStore $dataStore;

    /**
     * Flag to enable or disable the analyzer.
     */
    protected bool $enabled;

    /**
     * Indicates if this analyzer scans request payload content.
     */
    protected bool $scansPayload = false;

    /**
     * Determines if this analyzer is active (makes external requests)
     * or passive (only analyzes current request data).
     */
    protected bool $active = false;

    /**
     * Cache TTL in seconds.
     */
    protected int $cacheTtl;

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
        return $this->scansPayload;
    }

    /**
     * Check if this analyzer is active (makes external requests)
     * or passive (only analyzes current request data).
     */
    public function isActive(): bool
    {
        return $this->active;
    }

    /**
     * Analyze the request.
     */
    abstract public function analyze(Request $request): float;
}
