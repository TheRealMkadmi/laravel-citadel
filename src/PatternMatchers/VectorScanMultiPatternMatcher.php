<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\PatternMatchers;

use FFI;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatch;

final class VectorScanMultiPatternMatcher implements MultiPatternMatcher
{
    private const HS_SUCCESS          = 0;
    private const HS_INVALID          = -1;
    private const HS_NOMEM            = -2;
    private const HS_SCAN_TERMINATED  = -3;
    private const HS_COMPILER_ERROR   = -4;
    private const HS_DB_VERSION_ERROR = -5;
    private const HS_DB_PLATFORM_ERROR= -6;
    private const HS_DB_MODE_ERROR    = -7;
    private const HS_BAD_ALIGN        = -8;
    private const HS_BAD_ALLOC        = -9;

    private const HS_FLAG_CASELESS    = 1;
    private const HS_FLAG_DOTALL      = 2;
    private const HS_FLAG_MULTILINE   = 4;
    private const HS_FLAG_SINGLEMATCH = 8;
    private const HS_FLAG_ALLOWEMPTY  = 16;
    private const HS_FLAG_UTF8        = 32;
    private const HS_FLAG_UCP         = 64;
    private const HS_FLAG_PREFILTER   = 128;
    private const HS_FLAG_SOM_LEFTMOST= 256;
    private const HS_FLAG_NONE        = 0;

    private const HS_MODE_BLOCK       = 1;
    private const HS_MODE_STREAM      = 2;
    private const HS_MODE_VECTORED    = 4;

    private const DEFAULT_LIBRARY_NAME_LINUX = 'libhs.so.5';
    private const DEFAULT_LIBRARY_NAME_DARWIN = 'libhs.dylib';
    private const DEFAULT_LIBRARY_NAME_WINDOWS = 'libhs.dll';
    private const CONFIG_LIBRARY_PATH_KEY = 'vectorscan.library_path';

    private const HS_CALLBACK_CONTINUE = 0;
    private const HS_SCAN_FLAG_NONE    = 0;

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

struct hs_platform_info;
typedef struct hs_platform_info hs_platform_info_t;

struct hs_database;
typedef struct hs_database hs_database_t;

typedef struct hs_compile_error {
    char *message;
    int expression;
} hs_compile_error_t;

struct hs_scratch;
typedef struct hs_scratch hs_scratch_t;

struct hs_stream;
typedef struct hs_stream hs_stream_t;

#define HS_SUCCESS              0
#define HS_INVALID              -1
#define HS_NOMEM                -2
#define HS_SCAN_TERMINATED      -3
#define HS_COMPILER_ERROR       -4
#define HS_DB_VERSION_ERROR     -5
#define HS_DB_PLATFORM_ERROR    -6
#define HS_DB_MODE_ERROR        -7
#define HS_BAD_ALIGN            -8
#define HS_BAD_ALLOC            -9

#define HS_FLAG_CASELESS        1
#define HS_FLAG_DOTALL          2
#define HS_FLAG_MULTILINE       4
#define HS_FLAG_SINGLEMATCH     8
#define HS_FLAG_ALLOWEMPTY      16
#define HS_FLAG_UTF8            32
#define HS_FLAG_UCP             64
#define HS_FLAG_PREFILTER       128
#define HS_FLAG_SOM_LEFTMOST     256
#define HS_FLAG_NONE            0

#define HS_MODE_BLOCK           1
#define HS_MODE_NOSTREAM        1
#define HS_MODE_STREAM          2
#define HS_MODE_VECTORED        4

hs_error_t hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch);
hs_error_t hs_free_scratch(hs_scratch_t *scratch);
hs_error_t hs_free_compile_error(hs_compile_error_t *error);
hs_error_t hs_free_database(hs_database_t *db);

hs_error_t hs_compile_multi(const char *const * expressions,
                            const unsigned int * flags,
                            const unsigned int * ids,
                            unsigned int elements,
                            unsigned int mode,
                            const hs_platform_info_t * platform,
                            hs_database_t ** db,
                            hs_compile_error_t ** error);

typedef int (*match_event_handler)(unsigned int id,
                                   unsigned long long from,
                                   unsigned long long to,
                                   unsigned int flags,
                                   void *context);

hs_error_t hs_scan(const hs_database_t *db, const char *data,
                   unsigned int length, unsigned int flags,
                   hs_scratch_t *scratch, match_event_handler onEvent,
                   void *context);
CDEF;

            $this->ffi = FFI::cdef($cdef, $foundPath);
        } catch (\Throwable $e) {
            $errorMessage = "Error loading libvectorscan library: {$e->getMessage()}";
            Log::error($errorMessage);
            throw $e;
        }
    }

    private function compilePatterns(): void
    {
        Log::debug('Starting vectorscan pattern compilation.');
        $count = count($this->patterns);
        if ($count === 0) {
            Log::warning('Vectorscan compilation attempted with zero patterns.');
            $this->db = null;
            $this->scratch = null;
            return; // Early return if no patterns
        }

        // Prepare arrays for bulk compilation
        $exprs = $this->ffi->new("const char*[$count]");
        $flags = $this->ffi->new("unsigned int[$count]");
        $ids = $this->ffi->new("unsigned int[$count]");

        foreach ($this->patterns as $i => $pattern) {
            $len = strlen($pattern);
            $cPattern = $this->ffi->new("char[" . ($len + 1) . "]", false);
            FFI::memcpy($cPattern, $pattern, $len);
            $cPattern[$len] = "\0";

            $exprs[$i] = $cPattern;
            $flags[$i] = self::HS_FLAG_SINGLEMATCH | self::HS_FLAG_DOTALL;
            $ids[$i] = $i;
        }

        $dbPtr = $this->ffi->new("hs_database_t*[1]");
        $errorPtr = $this->ffi->new("hs_compile_error_t*[1]");

        Log::debug("Calling hs_compile_multi with {$count} patterns. Mode: " . self::HS_MODE_BLOCK);
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

        if ($ret !== self::HS_SUCCESS) {
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

            $logMessage = "Pattern compilation failed with error code: {$ret}.";
            if ($patternIndex >= 0 && $patternIndex < $count) {
                $problematicPattern = $this->patterns[$patternIndex] ?? 'unknown pattern';
                $logMessage .= " Error related to pattern #{$patternIndex}: '{$problematicPattern}'.";
            }
            $logMessage .= " Message: {$errorMessage}";
            Log::error($logMessage);

            throw new \RuntimeException($logMessage);
        }

        $this->db = $dbPtr[0];
        Log::info("libvectorscan patterns compiled successfully. Database pointer: " . ($this->db ? "valid" : "invalid"));

        $scratchPtr = $this->ffi->new("hs_scratch_t*[1]");
        Log::debug("Allocating vectorscan scratch space.");
        $ret = $this->ffi->{"hs_alloc_scratch"}($this->db, FFI::addr($scratchPtr[0]));
        if ($ret !== self::HS_SUCCESS) {
            Log::error("Failed to allocate libvectorscan scratch space with error code: {$ret}");
            $this->ffi->{"hs_free_database"}($this->db);
            throw new \RuntimeException("Failed to allocate libvectorscan scratch space with error code: {$ret}");
        }
        $this->scratch = $scratchPtr[0];
        Log::info("libvectorscan scratch space allocated successfully. Scratch pointer: " . ($this->scratch ? "valid" : "invalid"));
        Log::debug('Finished vectorscan pattern compilation and scratch allocation.');
    }

    public function scan(string $data): array
    {
        Log::debug("scan() called with data length: " . strlen($data));
        
        if (!isset($this->db) || !isset($this->scratch)) {
            Log::error("Attempted scan with uninitialized database or scratch space. DB: " . (isset($this->db) ? "set" : "null") . 
                       ", Scratch: " . (isset($this->scratch) ? "set" : "null"));
            throw new \RuntimeException("Vectorscan database or scratch space not initialized.");
        }
        
        if (empty($data)) {
            Log::debug("Skipping scan for empty data.");
            return []; // Avoid scanning empty data
        }

        $matchesFound = [];
        Log::debug("Preparing callback for hs_scan. Data length: " . strlen($data) . ", Data preview: '" . 
                  (strlen($data) > 50 ? substr($data, 0, 50) . "..." : $data) . "'");

        $callbackClosure = function ($id, $fromRaw, $toRaw, int $flags, $context) use (&$matchesFound, $data): int {
            Log::debug("Full data => {$data}");
            Log::debug("Vectorscan match callback fired: id={$id}, from={$fromRaw}, to={$toRaw}, flags={$flags}");

            if (!isset($this->patterns[$id])) {
                Log::warning("Callback received invalid pattern ID: {$id}, max valid ID: " . (count($this->patterns) - 1));
                return self::HS_CALLBACK_CONTINUE;
            }

            $fromInt = (int)$fromRaw;
            $toInt = (int)$toRaw;

            if ($fromInt < 0 || $toInt < $fromInt || $toInt > strlen($data)) {
                Log::error("Invalid match offsets: from={$fromInt}, to={$toInt}, data_len=" . strlen($data));
                return self::HS_CALLBACK_CONTINUE;
            }

            $matchText = substr($data, $fromInt, $toInt - $fromInt);
            Log::debug("Match extracted: '{$matchText}' for pattern: '{$this->patterns[$id]}'");

            $matchesFound[] = new MultiPatternMatch(
                id: $id,
                from: $fromInt,
                to: $toInt,
                flags: $flags,
                matchedSubstring: $matchText,
                originalPattern: $this->patterns[$id]
            );
            
            return self::HS_CALLBACK_CONTINUE;
        };

        Log::debug("Calling hs_scan function with database pointer: " . ($this->db ? "valid" : "invalid") . 
                  " and scratch pointer: " . ($this->scratch ? "valid" : "invalid"));
        $ret = $this->ffi->{"hs_scan"}(
            $this->db,
            $data,
            strlen($data),
            self::HS_SCAN_FLAG_NONE,
            $this->scratch,
            $callbackClosure,
            NULL
        );

        if ($ret < self::HS_SUCCESS && $ret !== self::HS_SCAN_TERMINATED) {
            Log::error("libvectorscan hs_scan failed with error code: {$ret}, HS_SUCCESS={" . self::HS_SUCCESS . 
                      "}, HS_SCAN_TERMINATED={" . self::HS_SCAN_TERMINATED . "}");
            throw new \RuntimeException("libvectorscan hs_scan failed with error code: {$ret}");
        }

        Log::info("libvectorscan hs_scan completed with return code: {$ret}. Found " . count($matchesFound) . " matches.");

        foreach ($matchesFound as $index => $match) {
            Log::debug("Match #{$index}: ID={$match->id}, from={$match->from}, to={$match->to}, flags={$match->flags}, matchedSubstring='{$match->matchedSubstring}'");
        }

        Log::debug("Scan complete. Returning " . count($matchesFound) . " matches.");
        return $matchesFound;
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
