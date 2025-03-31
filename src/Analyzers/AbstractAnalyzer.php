<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\AnalyzerType;

/**
 * Base class for all request analyzers with common functionality
 */
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
     * Cache TTL in seconds.
     */
    protected int $cacheTtl = 3600;

    /**
     * Whether this analyzer operates in blocking or monitoring mode.
     */
    protected AnalyzerType $analyzerType = AnalyzerType::BLOCKING;

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
        // Additional check for external resources analyzers
        if ($this->usesExternalResources() && !config('citadel.external_analyzers.enabled', true)) {
            // Log that external resource usage is disabled
            Log::debug('Citadel: External analyzer {analyzer} disabled by global setting', [
                'analyzer' => $this->getIdentifier(),
            ]);
            return false;
        }
        
        return $this->enabled;
    }

    /**
     * Check if this analyzer requires the request body for analysis.
     * Default is false, override in specific analyzers as needed.
     */
    public function requiresRequestBody(): bool
    {
        return false;
    }

    /**
     * Check if this analyzer makes external API calls or resource requests.
     * Default is false, override in specific analyzers as needed.
     */
    public function usesExternalResources(): bool
    {
        return false;
    }

    /**
     * Get the analyzer's operating mode.
     */
    public function getAnalyzerType(): AnalyzerType
    {
        return $this->analyzerType;
    }

    /**
     * Get a unique identifier for this analyzer type.
     * By default, uses the class basename, but can be overridden.
     */
    public function getIdentifier(): string
    {
        return class_basename($this);
    }

    /**
     * Analyze the request.
     */
    abstract public function analyze(Request $request): float;
}
