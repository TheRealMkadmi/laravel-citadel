<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class SpamminessAnalyzer implements IRequestAnalyzer
{
    /**
     * The data store for caching results.
     *
     * @var \TheRealMkadmi\Citadel\DataStore\DataStore
     */
    protected DataStore $dataStore;

    /**
     * Cache TTL in seconds
     * 
     * @var int
     */
    protected int $cacheTtl;

    /**
     * Flag to enable or disable the analyzer
     * 
     * @var bool
     */
    protected bool $enabled;

    /**
     * Known suspicious patterns in request payloads
     * 
     * @var array
     */

    /**
     * Constructor.
     * 
     * @param \TheRealMkadmi\Citadel\DataStore\DataStore $dataStore
     */
    public function __construct(DataStore $dataStore)
    {
        $this->dataStore = $dataStore;
        
           }

    /**
     * Analyze the request payload.
     *
     * @param Request $request
     * @return float
     */
    public function analyze(Request $request): float
    {

        if (!$this->enabled) {
            return 0.0;
        }
        $score = 0.0;
        return $score;
    }
    
    
}