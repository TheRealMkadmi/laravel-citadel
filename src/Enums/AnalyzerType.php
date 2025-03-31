<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Enums;

/**
 * Defines analyzer capabilities
 */
class AnalyzerType
{
    /**
     * Analyzer capability flags - define what each analyzer can do
     */
    public const REQUIRES_REQUEST_BODY = 'requires_request_body';
    public const USES_EXTERNAL_RESOURCES = 'uses_external_resources';
}