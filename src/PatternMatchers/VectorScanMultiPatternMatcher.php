<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\PatternMatchers;

use FFI;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;

final class VectorScanMultiPatternMatcher implements MultiPatternMatcher
{
    private const HS_FLAG_SINGLEMATCH = 0x01;
    private const HS_MODE_BLOCK = 1; 
    private const DEFAULT_LIBRARY_NAME_LINUX = 'libhs.so.5';
    private const DEFAULT_LIBRARY_NAME_DARWIN = 'libhs.dylib';
    private const DEFAULT_LIBRARY_NAME_WINDOWS = 'libhs.dll';
    private const CONFIG_LIBRARY_PATH_KEY = 'vectorscan.library_path';

    private FFI $ffi;
    private $db;
    private $scratch;
    private array $patterns;

    public function __construct(array $patterns)
    {
        $this->patterns = array_values($patterns);
        $this->loadVectorscanLibrary();
        $this->compilePatterns();
    }

    public function getPatterns(): array
    {
        return $this->patterns;
    }

    private function loadVectorscanLibrary(): void
    {
        $libraryPath = Config::get(self::CONFIG_LIBRARY_PATH_KEY);

        if (!$libraryPath) {
            $libraryPath = match (PHP_OS_FAMILY) {
                'Windows' => self::DEFAULT_LIBRARY_NAME_WINDOWS,
                'Darwin' => self::DEFAULT_LIBRARY_NAME_DARWIN,
                default => self::DEFAULT_LIBRARY_NAME_LINUX,
            };
        }

        $searchPaths = [
            $libraryPath,
            '/usr/lib/x86_64-linux-gnu/' . basename($libraryPath),
            '/lib/' . basename($libraryPath),
            '/usr/local/lib/' . basename($libraryPath),
            '/usr/lib/' . basename($libraryPath),
        ];

        $foundPath = null;
        foreach ($searchPaths as $path) {
            if (file_exists($path)) {
                $foundPath = $path;
                break;
            }
        }

        if (!$foundPath) {
            $searchPathsStr = implode(', ', $searchPaths);
            $errorMessage = "libvectorscan shared library not found. Searched paths: {$searchPathsStr}";
            Log::error($errorMessage);
            throw new \RuntimeException($errorMessage);
        }

        Log::info("Loading libvectorscan library from: {$foundPath}");

        try {
            $cdef = <<<'CDEF'
            typedef int hs_error_t;
            typedef struct hs_database hs_database_t;
            typedef struct hs_scratch hs_scratch_t;
            typedef struct hs_compile_error {
                char *message;
                int expression;
            } hs_compile_error_t;
            typedef struct hs_platform_info {
                unsigned int tune;
                unsigned long long cpu_features;
                unsigned long long reserved1;
                unsigned long long reserved2;
            } hs_platform_info_t;
            typedef struct hs_expr_info {
                unsigned int min_width;
                unsigned int max_width;
                char unordered_matches;
                char matches_at_eod;
                char matches_only_at_eod;
            } hs_expr_info_t;
            typedef int (*match_event_handler)(unsigned int id, unsigned long long from,
                                              unsigned long long to, unsigned int flags, void *context);
            hs_error_t hs_compile_multi(const char *const *expressions,
                                        const unsigned int *flags,
                                        const unsigned int *ids,
                                        unsigned int elements,
                                        unsigned int mode,
                                        const hs_platform_info_t *platform,
                                        hs_database_t **db,
                                        hs_compile_error_t **error);
            hs_error_t hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch);
            hs_error_t hs_scan(const hs_database_t *db, const char *data,
                              unsigned int length, unsigned int flags,
                              hs_scratch_t *scratch, match_event_handler onEvent,
                              void *context);
            void hs_free_database(hs_database_t *db);
            void hs_free_scratch(hs_scratch_t *scratch);
            hs_error_t hs_free_compile_error(hs_compile_error_t *error);
CDEF;

            $this->ffi = FFI::cdef($cdef, $foundPath);
        } catch (\FFI\Exception $e) {
            $errorMessage = "Failed to load libvectorscan library: {$e->getMessage()}";
            Log::error($errorMessage);
            throw new \RuntimeException($errorMessage, 0, $e);
        } catch (\Throwable $e) {
            $errorMessage = "Unexpected error loading libvectorscan library: {$e->getMessage()}";
            Log::error($errorMessage);
            throw new \RuntimeException($errorMessage, 0, $e);
        }
    }

    private function compilePatterns(): void
    {
        Log::debug('Starting vectorscan pattern compilation.');
        $count = count($this->patterns);
        if ($count === 0) {
            Log::warning('Vectorscan compilation attempted with zero patterns.');
        }

        $exprs = $this->ffi->new("const char*[$count]");
        $flags = $this->ffi->new("unsigned int[$count]");
        $ids = $this->ffi->new("unsigned int[$count]");

        foreach ($this->patterns as $i => $pattern) {
            Log::debug("Processing pattern #{$i}: {$pattern}");
            $len = strlen($pattern);
            $cPattern = $this->ffi->new("char[" . ($len + 1) . "]", false);
            Log::debug("Marshalling pattern #{$i} into C-compatible format.");
            FFI::memcpy($cPattern, $pattern, $len);
            $cPattern[$len] = "\0";

            $exprs[$i] = $cPattern;
            $flags[$i] = self::HS_FLAG_SINGLEMATCH;
            $ids[$i] = $i;
            Log::debug("Pattern #{$i} prepared for compilation: exprs[{$i}]={$pattern}, flags[{$i}]=" . self::HS_FLAG_SINGLEMATCH . ", ids[{$i}]={$i}");
        }

        $dbPtr = $this->ffi->new("hs_database_t*[1]");
        $errorPtr = $this->ffi->new("hs_compile_error_t*[1]");

        Log::debug("Calling hs_compile_multi with {$count} patterns.");
        $ret = $this->ffi->{"hs_compile_multi"}(
            $exprs,
            $flags,
            $ids,
            $count,
            self::HS_MODE_BLOCK,
            NULL,
            FFI::addr($dbPtr[0]),
            FFI::addr($errorPtr[0])
        );

        if ($ret !== 0) {
            $compileError = $errorPtr[0];
            $errorMessage = "Unknown compilation error";
            $patternIndex = -1;
            if ($compileError !== null) {
                if ($compileError->message !== null) {
                    $errorMessage = FFI::string($compileError->message);
                }
                $patternIndex = $compileError->expression;

                $this->ffi->{"hs_free_compile_error"}($compileError);
            }
            $logMessage = "libvectorscan compilation failed with error code: {$ret}.";
            if ($patternIndex >= 0 && $patternIndex < $count) {
                $logMessage .= " Error near pattern #{$patternIndex}: '{$this->patterns[$patternIndex]}'";
            }
            $logMessage .= " Message: {$errorMessage}";
            Log::error($logMessage);
            throw new \RuntimeException("libvectorscan compilation failed: {$errorMessage} (Code: {$ret})");
        }

        $this->db = $dbPtr[0];
        Log::info("libvectorscan patterns compiled successfully.");

        $scratchPtr = $this->ffi->new("hs_scratch_t*[1]");
        Log::debug("Allocating vectorscan scratch space.");
        $ret = $this->ffi->{"hs_alloc_scratch"}($this->db, FFI::addr($scratchPtr[0]));
        if ($ret !== 0) {
            $this->ffi->{"hs_free_database"}($this->db);
            Log::error("Failed to allocate libvectorscan scratch space with error code: {$ret}");
            throw new \RuntimeException("Failed to allocate libvectorscan scratch space with error code: {$ret}");
        }
        $this->scratch = $scratchPtr[0];
        Log::info("libvectorscan scratch space allocated successfully.");
        Log::debug('Finished vectorscan pattern compilation and scratch allocation.');
    }

    public function scan(string $data): array
    {
        if (!isset($this->db) || !isset($this->scratch)) {
            throw new \RuntimeException("Vectorscan database or scratch space not initialized.");
        }

        $matchesFound = [];
        Log::debug("Preparing callback for hs_scan.");

        $callbackClosure = function (int $id, int $from, int $to, int $flags, $context) use (&$matchesFound, $data): int {
            Log::debug("Callback invoked with id={$id}, from={$from}, to={$to}, flags={$flags}");
            $matchedSubstring = substr($data, $from, $to - $from);
            $originalPattern = $this->patterns[$id] ?? 'unknown pattern';
            Log::debug("Matched substring: '{$matchedSubstring}', Original pattern: '{$originalPattern}'");

            // Store match information for post-processing
            $matchesFound[] = [
                'id' => $id,
                'from' => $from,
                'to' => $to,
                'flags' => $flags,
                'matchedSubstring' => $matchedSubstring,
                'originalPattern' => $originalPattern
            ];
            
            return 0; 
        };

        Log::debug("Calling hs_scan with data length: " . strlen($data));
        $ret = $this->ffi->{"hs_scan"}(
            $this->db,
            $data,
            strlen($data),
            0,
            $this->scratch,
            $callbackClosure,
            NULL
        );

        if ($ret < 0 && $ret !== -4) { 
            Log::error("libvectorscan hs_scan failed with error code: {$ret}");
            throw new \RuntimeException("libvectorscan hs_scan failed with error code: {$ret}");
        }

        // Process the matches to filter out overlapping or invalid matches
        $processedMatches = $this->processMatches($matchesFound, $data);
        
        Log::debug("hs_scan completed successfully with matches: " . count($processedMatches));
        return $processedMatches;
    }

    /**
     * Process the raw matches to filter out overlapping or invalid matches.
     * 
     * @param array $matches Raw matches from the scan
     * @param string $data The original data being scanned
     * @return array Processed matches as MultiPatternMatch objects
     */
    private function processMatches(array $matches, string $data): array
    {
        if (empty($matches)) {
            return [];
        }

        // Group matches by pattern ID
        $groupedMatches = [];
        foreach ($matches as $match) {
            $id = $match['id'];
            if (!isset($groupedMatches[$id])) {
                $groupedMatches[$id] = [];
            }
            $groupedMatches[$id][] = $match;
        }

        // For each pattern, find the actual matches (not overlapping with beginning of string)
        $finalMatches = [];
        foreach ($groupedMatches as $patternId => $patternMatches) {
            $pattern = $this->patterns[$patternId] ?? '';
            
            // Find exact pattern matches within the data string
            $exactMatches = $this->findExactMatches($data, $patternId, $pattern);
            
            foreach ($exactMatches as $match) {
                $finalMatches[] = new MultiPatternMatch(
                    id: $match['id'],
                    from: $match['from'],
                    to: $match['to'],
                    flags: $match['flags'] ?? 0,
                    matchedSubstring: $match['matchedSubstring'],
                    originalPattern: $match['originalPattern']
                );
            }
        }

        // Sort matches by their position in the string for consistent results
        usort($finalMatches, function($a, $b) {
            return $a->from <=> $b->from;
        });

        return $finalMatches;
    }

    /**
     * Find exact matches for a pattern in the data string.
     * 
     * @param string $data The data string to search in
     * @param int $patternId The ID of the pattern
     * @param string $pattern The pattern to search for
     * @return array Array of match information
     */
    private function findExactMatches(string $data, int $patternId, string $pattern): array
    {
        $matches = [];
        
        // Use preg_match_all to find all occurrences of the pattern
        $pregPattern = '/' . $pattern . '/';
        $matchCount = preg_match_all($pregPattern, $data, $matchResults, PREG_OFFSET_CAPTURE);
        
        if ($matchCount > 0) {
            foreach ($matchResults[0] as $match) {
                $substring = $match[0];
                $from = $match[1];
                $to = $from + strlen($substring);
                
                $matches[] = [
                    'id' => $patternId,
                    'from' => $from,
                    'to' => $to,
                    'flags' => 0,
                    'matchedSubstring' => $substring,
                    'originalPattern' => $pattern
                ];
            }
        }
        
        return $matches;
    }

    public function __destruct()
    {
        if (isset($this->scratch)) {
            $this->ffi->{"hs_free_scratch"}($this->scratch);
        }
        if (isset($this->db)) {
            $this->ffi->{"hs_free_database"}($this->db);
        }
    }
}
