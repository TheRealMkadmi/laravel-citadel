<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class PayloadAnalyzer extends AbstractAnalyzer
{
    /**
     * Known suspicious patterns in request payloads
     */
    protected array $suspiciousPatterns;

    /**
     * Maximum analysis score
     */
    protected float $maxScore;

    /**
     * Score threshold for potential threats
     */
    protected float $threatThreshold;

    /**
     * This analyzer requires a request body to function
     */
    public function requiresRequestBody(): bool
    {
        return true;
    }

    /**
     * This analyzer doesn't use external resources
     */
    public function usesExternalResources(): bool
    {
        return false;
    }

    /**
     * Cached entropy calculations
     */
    protected array $entropyCache = [];

    /**
     * Constructor.
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct($dataStore);

        // Load all configuration values using Laravel's config helper
        $this->enabled = config('citadel.payload.enable_payload_analyzer', true);
        $this->cacheTtl = config('citadel.payload.cache_ttl', config('citadel.cache.payload_analysis_ttl', 3600));
        $this->maxScore = config('citadel.payload.max_score', 100.0);
        $this->threatThreshold = config('citadel.payload.threat_threshold', 40.0);

        // Load suspicious patterns from config - only once during initialization
        $this->suspiciousPatterns = config('citadel.payload.suspicious_patterns') ?? $this->getDefaultPatterns();
    }

    /**
     * Analyze the request payload.
     */
    public function analyze(Request $request): float
    {
        if (! $this->enabled) {
            return 0.0;
        }

        // Use the getFingerprint request macro to get the fingerprint
        $fingerprint = $request->getFingerprint();
        $cacheKey = "payload_analysis:{$fingerprint}";

        // Check if we have a cached result
        $cached = $this->dataStore->getValue($cacheKey);
        if ($cached !== null) {
            return (float) $cached;
        }

        // Extract and normalize all request data for comprehensive analysis
        $analysisData = $this->extractRequestData($request);

        // Calculate score using advanced pattern detection
        $analysisResult = $this->performAdvancedAnalysis($analysisData, $request);

        // Cache the result
        $this->dataStore->setValue($cacheKey, $analysisResult['score'], $this->cacheTtl);

        // Log high-risk detections for security monitoring
        if ($analysisResult['score'] >= $this->threatThreshold) {
            $this->logSecurityThreat($request, $analysisResult);
        }

        return $analysisResult['score'];
    }

    /**
     * Extract all relevant data from the request for analysis.
     */
    protected function extractRequestData(Request $request): array
    {
        return [
            // Get all request body data - normalized to detect obfuscation
            'body' => $request->all(),

            // Get raw request body if available (limit size to reduce processing overhead)
            'raw_body' => Str::limit($request->getContent(), 8192, ''),

            // Get JSON-specific data if present
            'json' => $request->isJson() ? $request->json()->all() : [],

            // Check query string parameters
            'query' => $request->query(),
            'query_string' => $request->getQueryString() ?? '',

            // Extract headers for analysis
            'headers' => $request->headers->all(),
            'user_agent' => $request->userAgent() ?? '',

            // Extract cookies
            'cookies' => $request->cookies->all(),

            // Extract request metadata
            'method' => $request->method(),
            'path' => $request->path(),
            'url' => $request->url(),
            'content_type' => $request->header('Content-Type'),
            'content_length' => (int) $request->header('Content-Length', '0'),

            // Extract file uploads for analysis if present
            'has_files' => $request->hasFile('*'),
            'file_counts' => $request->hasFile('*') ? count($request->allFiles()) : 0,
        ];
    }

    /**
     * Normalize data to detect obfuscation attempts.
     */
    protected function normalizeData(array $data): string
    {
        // Only encode the data once
        $normalized = json_encode($data);
        if (! $normalized) {
            return '';
        }

        // Apply normalization techniques to reveal obfuscated code (optimize replacements)
        $patterns = ['\\\\x', '\\\\u', '%20', '%27', '%22', '%3C', '%3E', '%28', '%29'];
        $normalized = str_replace($patterns, '', $normalized);

        // Check for base64 encoded payloads (with optimization for large payloads)
        if (strlen($normalized) > 10000) {
            // For large payloads, sample only portions to avoid performance issues
            $sample = substr($normalized, 0, 3000).
                     substr($normalized, intval(strlen($normalized) / 2), 2000).
                     substr($normalized, -3000);
            $matches = [];
            preg_match_all('/[a-zA-Z0-9+\/=]{20,}/', $sample, $matches);
        } else {
            preg_match_all('/[a-zA-Z0-9+\/=]{20,}/', $normalized, $matches);
        }

        // Limit the number of matches processed to prevent DoS
        $processedMatches = array_slice($matches[0] ?? [], 0, 10);

        foreach ($processedMatches as $encoded) {
            try {
                $decoded = base64_decode($encoded, true);
                if ($decoded !== false && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $decoded) === 0) {
                    $normalized .= ' '.$decoded;
                }
            } catch (\Exception $e) {
                // Ignore failed decode attempts
            }
        }

        return $normalized;
    }

    /**
     * Perform advanced analysis on the request data.
     *
     * @param  array  $data  Extracted request data
     * @return array Analysis result with score and detected threats
     */
    protected function performAdvancedAnalysis(array $data, Request $request): array
    {
        $score = 0.0;
        $threats = [];
        $evidences = [];

        // 1. Check for known malicious patterns across all data
        // Only normalize and analyze if there's actual content to check
        if (! empty($data['body']) || ! empty($data['query']) || ! empty($data['raw_body'])) {
            $textToAnalyze = $this->prepareTextForAnalysis($data);

            foreach ($this->suspiciousPatterns as $category => $patternGroup) {
                foreach ($patternGroup['patterns'] as $name => $pattern) {
                    // Skip patterns that don't apply to the current request context
                    if ($this->shouldSkipPattern($pattern, $data)) {
                        continue;
                    }

                    preg_match_all($pattern['regex'], $textToAnalyze, $matches, PREG_OFFSET_CAPTURE);

                    if (! empty($matches[0])) {
                        $matchCount = count($matches[0]);
                        $matchPenalty = $pattern['score'] * min($matchCount, $pattern['max_matches'] ?? 3);
                        $score += $matchPenalty;

                        $threats[$category][] = $name;
                        $evidences[$name] = [
                            'count' => $matchCount,
                            'score_added' => $matchPenalty,
                            'examples' => array_slice($matches[0], 0, 3),
                        ];
                    }
                }
            }
        }

        // 2. Check for anomalies in request structure
        $anomalyScore = $this->detectRequestAnomalies($data, $request);
        $score += $anomalyScore['score'];
        if ($anomalyScore['score'] > 0) {
            $threats['anomalies'] = $anomalyScore['detected'];
            $evidences['anomalies'] = $anomalyScore['evidence'];
        }

        // 3. Check for entropy (randomness) in request parameters
        // High entropy can indicate obfuscated or encrypted malicious code
        if (! empty($data['query']) || ! empty($data['body'])) {
            $entropyScore = $this->calculateEntropyScore($data);
            $score += $entropyScore['score'];
            if ($entropyScore['score'] > 0) {
                $threats['entropy'] = $entropyScore['details'];
            }
        }

        // 4. Contextual analysis - check if payload makes sense for the endpoint
        $contextScore = $this->analyzeRequestContext($data, $request);
        $score += $contextScore;

        // 5. Historical pattern analysis for this fingerprint
        $historyScore = $this->analyzeHistoricalPatterns($request->getFingerprint(), $data);
        $score += $historyScore['score'];

        // Ensure score doesn't exceed maximum
        $score = min($score, $this->maxScore);

        return [
            'score' => $score,
            'threats' => $threats,
            'evidences' => $evidences,
            'timestamp' => now()->toDateTimeString(),
        ];
    }

    /**
     * Determine if a pattern should be skipped based on request context
     */
    protected function shouldSkipPattern(array $pattern, array $data): bool
    {
        // Skip SQL injection checks for GET requests with no query parameters
        if (isset($pattern['context']) && $pattern['context'] === 'sql' &&
            $data['method'] === 'GET' && empty($data['query'])) {
            return true;
        }

        // Skip file inclusion patterns for requests with no file uploads
        if (isset($pattern['context']) && $pattern['context'] === 'file' &&
            ! $data['has_files']) {
            return true;
        }

        return false;
    }

    /**
     * Combine all relevant request data into a single text for analysis.
     */
    protected function prepareTextForAnalysis(array $data): string
    {
        // Normalize body once for all pattern matching
        $normalizedBody = $this->normalizeData($data['body'] ?? []);

        $elements = [
            $data['raw_body'] ?? '',
            $normalizedBody,
            ! empty($data['json']) ? json_encode($data['json']) : '',
            $data['query_string'] ?? '',
            ! empty($data['query']) ? json_encode($data['query']) : '',
            $data['user_agent'] ?? '',
            $data['path'] ?? '',
        ];

        return Str::of(implode(' ', array_filter($elements)))
            ->limit(16384) // Limit total size to prevent performance issues
            ->toString();
    }

    /**
     * Detect anomalies in the request structure.
     */
    protected function detectRequestAnomalies(array $data, Request $request): array
    {
        $score = 0;
        $detected = [];
        $evidence = [];

        // Check request size - larger payloads can be suspicious
        $contentLength = $data['content_length'];
        $maxSize = config('citadel.payload.max_size', 1048576); // Default 1MB

        if ($contentLength > $maxSize) {
            $sizeScore = config('citadel.payload.large_payload_score', 20.0);
            $score += $sizeScore;
            $detected[] = 'large_payload';
            $evidence['large_payload'] = [
                'size' => $contentLength,
                'max_allowed' => $maxSize,
                'score_added' => $sizeScore,
            ];
        }

        // Check for very large number of parameters which can indicate automation
        $paramCount = count($data['body'] ?? []);
        $maxParams = config('citadel.payload.max_params', 100);

        if ($paramCount > $maxParams) {
            $paramsScore = config('citadel.payload.many_params_score', 15.0);
            $score += $paramsScore;
            $detected[] = 'many_parameters';
            $evidence['many_parameters'] = [
                'count' => $paramCount,
                'max_allowed' => $maxParams,
                'score_added' => $paramsScore,
            ];
        }

        // Detect mismatched content types
        if ($data['content_type'] && Str::contains($data['content_type'], 'application/json') && ! $request->isJson()) {
            $score += config('citadel.payload.mismatched_content_type_score', 10.0);
            $detected[] = 'mismatched_content_type';
        }

        // Detect unusual header combinations
        if ($this->hasUnusualHeaderCombination($data['headers'])) {
            $score += config('citadel.payload.unusual_headers_score', 15.0);
            $detected[] = 'unusual_headers';
        }

        // Detect inconsistent Accept headers
        if ($this->hasInconsistentAcceptHeaders($data['headers'])) {
            $score += config('citadel.payload.inconsistent_accept_headers_score', 10.0);
            $detected[] = 'inconsistent_accept_headers';
        }

        return [
            'score' => $score,
            'detected' => $detected,
            'evidence' => $evidence,
        ];
    }

    /**
     * Check for unusual header combinations that might indicate automated tools.
     */
    protected function hasUnusualHeaderCombination(array $headers): bool
    {
        $headers = array_change_key_case($headers, CASE_LOWER);

        // Check for contradictory browser headers
        if (isset($headers['user-agent']) && Str::contains(strtolower($headers['user-agent'][0] ?? ''), 'chrome')) {
            // Chrome browser should have certain expected headers
            if (! isset($headers['sec-ch-ua']) || ! isset($headers['sec-ch-ua-mobile'])) {
                return true;
            }
        }

        // No origin or referer on POST requests is suspicious
        if (request()->isMethod('post') && ! isset($headers['origin']) && ! isset($headers['referer'])) {
            return true;
        }

        return false;
    }

    /**
     * Check for inconsistencies between Accept headers.
     */
    protected function hasInconsistentAcceptHeaders(array $headers): bool
    {
        $headers = array_change_key_case($headers, CASE_LOWER);

        // Check for inconsistency between Accept and Accept-Language
        if (isset($headers['accept-language']) && isset($headers['accept'])) {
            $acceptLanguage = strtolower($headers['accept-language'][0] ?? '');
            $accept = strtolower($headers['accept'][0] ?? '');

            // If Accept header claims to accept HTML but language header is empty or wildcard
            if (Str::contains($accept, 'text/html') && ($acceptLanguage === '*' || empty($acceptLanguage))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Calculate entropy score for request data.
     * High entropy strings can indicate obfuscation.
     */
    protected function calculateEntropyScore(array $data): array
    {
        $totalScore = 0;
        $details = [];

        // Examine query parameters
        foreach ($data['query'] as $param => $value) {
            if (is_string($value) && strlen($value) > 20) {
                $entropy = $this->calculateStringEntropy($value);
                if ($entropy > 4.5) { // High entropy threshold
                    $entropyScore = min(5.0 * ($entropy - 4.5), 20.0);
                    $totalScore += $entropyScore;
                    $details['high_entropy_query'][] = [
                        'param' => $param,
                        'entropy' => $entropy,
                        'score' => $entropyScore,
                    ];
                }
            }
        }

        // Examine body parameters
        if (is_array($data['body'])) {
            $this->recursiveEntropyCheck($data['body'], $totalScore, $details);
        }

        return [
            'score' => $totalScore,
            'details' => $details,
        ];
    }

    /**
     * Recursively check entropy in nested arrays.
     */
    protected function recursiveEntropyCheck(array $data, float &$totalScore, array &$details, string $path = ''): void
    {
        foreach ($data as $key => $value) {
            $currentPath = $path ? "{$path}.{$key}" : $key;

            if (is_array($value)) {
                $this->recursiveEntropyCheck($value, $totalScore, $details, $currentPath);
            } elseif (is_string($value) && strlen($value) > 20) {
                $entropy = $this->calculateStringEntropy($value);
                if ($entropy > 4.5) { // High entropy threshold
                    $entropyScore = min(5.0 * ($entropy - 4.5), 20.0);
                    $totalScore += $entropyScore;
                    $details['high_entropy_body'][] = [
                        'path' => $currentPath,
                        'entropy' => $entropy,
                        'score' => $entropyScore,
                    ];
                }
            }
        }
    }

    /**
     * Calculate Shannon entropy of a string.
     * Higher values indicate more randomness.
     */
    protected function calculateStringEntropy(string $string): float
    {
        // Cache entropy calculations to avoid recalculating for the same string
        $cacheKey = md5($string);
        if (isset($this->entropyCache[$cacheKey])) {
            return $this->entropyCache[$cacheKey];
        }

        $entropy = 0;
        $size = strlen($string);

        if ($size === 0) {
            return 0;
        }

        // For very large strings, sample to improve performance
        if ($size > 1000) {
            // Sample beginning, middle and end of string
            $sample = substr($string, 0, 300).
                      substr($string, intval($size / 2) - 150, 300).
                      substr($string, -300);
            $string = $sample;
            $size = strlen($string);
        }

        // Count character frequencies using optimized method
        $charFreq = [];
        for ($i = 0; $i < $size; $i++) {
            $char = $string[$i];
            $charFreq[$char] = ($charFreq[$char] ?? 0) + 1;
        }

        // Calculate entropy
        foreach ($charFreq as $frequency) {
            $probability = $frequency / $size;
            $entropy -= $probability * log($probability, 2);
        }

        // Cache the result
        $this->entropyCache[$cacheKey] = $entropy;

        // Limit cache size to prevent memory issues
        if (count($this->entropyCache) > 100) {
            // Remove random entries when cache gets too large
            array_shift($this->entropyCache);
        }

        return $entropy;
    }

    /**
     * Analyze the request in context of the accessed endpoint.
     */
    protected function analyzeRequestContext(array $data, Request $request): float
    {
        $score = 0;
        $method = $request->method();
        $path = $request->path();

        // Check if the method makes sense for the path
        // For example, POST to /login makes sense, but POST to /logout might not
        if ($method === 'POST' && Str::contains($path, ['logout', 'signout'])) {
            $score += config('citadel.payload.suspicious_request_method_score', 15.0);
        }

        // More context-specific checks can be added here

        return $score;
    }

    /**
     * Analyze historical patterns for this fingerprint.
     */
    protected function analyzeHistoricalPatterns(string $fingerprint, array $data): array
    {
        $historyKey = "payload_history:{$fingerprint}";
        $history = $this->dataStore->getValue($historyKey) ?? [];

        $score = 0;
        $currentData = [
            'timestamp' => now()->timestamp,
            'path' => $data['path'] ?? '',
            'method' => $data['method'] ?? '',
            'has_payload' => ! empty($data['body']) || ! empty($data['json']),
        ];

        // Update history with current request
        $history[] = $currentData;

        // Keep only the last 10 requests
        if (count($history) > 10) {
            $history = array_slice($history, -10);
        }

        // Check for suspicious patterns in history
        if (count($history) >= 3) {
            // Check for rapid identical requests
            $identicalRequests = 0;
            for ($i = count($history) - 2; $i >= 0; $i--) {
                if ($history[$i]['path'] === $currentData['path'] &&
                    $history[$i]['method'] === $currentData['method'] &&
                    $history[$i]['has_payload'] === $currentData['has_payload'] &&
                    ($currentData['timestamp'] - $history[$i]['timestamp']) < 60) { // Within a minute
                    $identicalRequests++;
                }
            }

            if ($identicalRequests >= 3) {
                $score += config('citadel.payload.repeated_identical_requests_score', 15.0);
            }

            // Check for sequential probing of different endpoints
            $uniquePaths = collect($history)->pluck('path')->unique()->count();
            if (count($history) >= 5 && $uniquePaths >= 4) { // Many different paths in short time
                $score += config('citadel.payload.sequential_probing_score', 20.0);
            }
        }

        // Store updated history with proper TTL
        $this->dataStore->setValue($historyKey, $history, $this->cacheTtl * 2);

        return [
            'score' => $score,
            'pattern_detected' => $score > 0,
        ];
    }

    /**
     * Log security threats for monitoring.
     */
    protected function logSecurityThreat(Request $request, array $analysisResult): void
    {
        Log::channel(config('citadel.log_channel', 'stack'))->warning(
            'Citadel: High-risk payload detected',
            [
                'ip' => $request->ip(),
                'fingerprint' => $request->getFingerprint(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'user_agent' => $request->userAgent(),
                'threats' => $analysisResult['threats'],
                'score' => $analysisResult['score'],
                'evidences' => $analysisResult['evidences'],
            ]
        );
    }

    /**
     * Get default patterns for payload analysis.
     */
    protected function getDefaultPatterns(): array
    {
        return [
            'sql_injection' => [
                'description' => 'SQL Injection attempts',
                'patterns' => [
                    'basic_sql' => [
                        'regex' => '/\b(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|alter\s+table|exec\s*\(|INFORMATION_SCHEMA|sysobjects|xp_cmdshell)\b/i',
                        'score' => 40.0,
                        'max_matches' => 2,
                    ],
                    'sql_function_abuse' => [
                        'regex' => '/\b(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|UTL_HTTP|DBMS_LDAP)\b/i',
                        'score' => 45.0,
                    ],
                    'sql_comments' => [
                        'regex' => '/(\-\-|\/\*|\*\/|#)\s*(.*)(=|<|>)/i',
                        'score' => 30.0,
                    ],
                    'sql_boolean' => [
                        'regex' => '/([\'"]\s*)\s*(OR|AND)\s*([\'"]?\s*[0-9]+\s*[=<>]\s*[0-9]+\s*[\'"]?)/i',
                        'score' => 50.0,
                    ],
                    'sql_batched' => [
                        'regex' => '/;\s*(select|insert|update|delete|drop|create|alter|grant|truncate|replace|load)/i',
                        'score' => 55.0,
                    ],
                ],
            ],

            'xss' => [
                'description' => 'Cross-Site Scripting attempts',
                'patterns' => [
                    'script_tags' => [
                        'regex' => '/<\s*script[^>]*>(.*?)<\s*\/\s*script\s*>/i',
                        'score' => 50.0,
                    ],
                    'event_handlers' => [
                        'regex' => '/\b(on(error|load|click|mouseover|focus|blur|change|submit|select|unload|beforeunload))\s*=/i',
                        'score' => 40.0,
                    ],
                    'javascript_protocol' => [
                        'regex' => '/\b(javascript|data|vbscript)\s*:/i',
                        'score' => 45.0,
                    ],
                    'dom_manipulation' => [
                        'regex' => '/\.(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.cookie|location)\s*=/i',
                        'score' => 40.0,
                    ],
                    'eval_functions' => [
                        'regex' => '/\b(eval|setTimeout|setInterval|Function|execScript)\s*\(/i',
                        'score' => 45.0,
                    ],
                    'html_obfuscation' => [
                        'regex' => '/&#x([0-9a-f]+);|&#([0-9]+);|\\\\x([0-9a-f]+)/i',
                        'score' => 30.0,
                        'max_matches' => 5,
                    ],
                ],
            ],

            'command_injection' => [
                'description' => 'Command injection attempts',
                'patterns' => [
                    'basic_injection' => [
                        'regex' => '/[;&|`]\s*(cat|tac|tail|head|sh|bash|cmd|powershell|nslookup|ping|wget|curl|nc|telnet|python|perl|ruby|php)\s/i',
                        'score' => 60.0,
                    ],
                    'command_chaining' => [
                        'regex' => '/\s*(?:;|&&|\|\||\|)\s*([a-z0-9_\-]+)/i',
                        'score' => 50.0,
                        'max_matches' => 2,
                    ],
                    'command_substitution' => [
                        'regex' => '/`([^`]+)`|\$\(([^)]+)\)|\$\{([^}]+)\}/i',
                        'score' => 55.0,
                    ],
                    'reverse_shell' => [
                        'regex' => '/(\/dev\/tcp|fsockopen|nc -e|bash -i|python -c .*socket|perl -e .*socket|ruby -e .*socket)/i',
                        'score' => 70.0,
                    ],
                    'data_exfil' => [
                        'regex' => '/(\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32|\/var\/www|\/home\/|SELECT.+FROM)/i',
                        'score' => 50.0,
                    ],
                ],
            ],

            'path_traversal' => [
                'description' => 'Directory traversal attempts',
                'patterns' => [
                    'basic_traversal' => [
                        'regex' => '/\.\.(\/|\\\\)(?:\.\.(\/|\\\\))+/i',
                        'score' => 50.0,
                    ],
                    'encoded_traversal' => [
                        'regex' => '/%2e%2e(\/|%2f|%5c)/i',
                        'score' => 55.0,
                    ],
                    'sensitive_files' => [
                        'regex' => '/(\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ|C:\\boot\.ini|win\.ini|web\.config|\.htaccess)/i',
                        'score' => 45.0,
                    ],
                    'log_file_access' => [
                        'regex' => '/(\/var\/log\/|\/logs\/|\/proc\/self\/|access_log|error_log|debug\.log)/i',
                        'score' => 40.0,
                    ],
                ],
            ],

            'file_inclusion' => [
                'description' => 'Remote and Local File Inclusion attempts',
                'patterns' => [
                    'remote_inclusion' => [
                        'regex' => '/(https?|ftp|php|data|expect):\/\/[^\s\'"]+/i',
                        'score' => 40.0,
                    ],
                    'wrapper_abuse' => [
                        'regex' => '/(php|data|expect|file|glob|phar|zip|rar|ogg|ssh2):\/\//i',
                        'score' => 50.0,
                    ],
                    'null_byte' => [
                        'regex' => '/\x00|%00|\\0/i',
                        'score' => 55.0,
                    ],
                ],
            ],

            'serialization' => [
                'description' => 'Serialization and deserialization attacks',
                'patterns' => [
                    'php_serialized_objects' => [
                        'regex' => '/O:[0-9]+:"[^"]+"/i',
                        'score' => 40.0,
                    ],
                    'java_serialized' => [
                        'regex' => '/rO0ABX[a-zA-Z0-9+\/=]+/i',
                        'score' => 45.0,
                    ],
                    'node_serialized' => [
                        'regex' => '/_\$\$ND_FUNC\$\$_/i',
                        'score' => 50.0,
                    ],
                ],
            ],

            'csrf' => [
                'description' => 'Cross-Site Request Forgery attempts',
                'patterns' => [
                    'origin_mismatch' => [
                        'regex' => '/<form.*?action=["\']https?:\/\/(?!your-domain)[^"\']+/i',
                        'score' => 30.0,
                    ],
                ],
            ],

            'authentication' => [
                'description' => 'Authentication bypass attempts',
                'patterns' => [
                    'bypass_patterns' => [
                        'regex' => '/^[\'";\s]*(?:or|and|true|false|like|1\s*=\s*1)[\s\'"]*/i',
                        'score' => 55.0,
                    ],
                ],
            ],
        ];
    }
}