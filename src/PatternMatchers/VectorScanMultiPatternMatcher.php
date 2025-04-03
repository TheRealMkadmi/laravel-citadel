<?php

/**
 * Todo: document this 
 * For a weird reason, can't install vectorscan from the package manager. Here's a workaround: 
 * wget https://security.ubuntu.com/ubuntu/pool/universe/v/vectorscan/libvectorscan5_5.4.11-2ubuntu1_amd64.deb
 * dpkg -i libvectorscan5_5.4.11-2ubuntu1_amd64.deb
 * apt install -f
 */

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\PatternMatchers;

use FFI;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;

final class VectorScanMultiPatternMatcher implements MultiPatternMatcher
{
    // Class constants for vectorscan flags and modes
    private const HS_FLAG_SINGLEMATCH = 0x01;
    private const HS_MODE_BLOCK = 1; 

    // Library path constants
    private const DEFAULT_LIBRARY_NAME_LINUX = 'libhs.so.5';
    private const DEFAULT_LIBRARY_NAME_DARWIN = 'libhs.dylib';
    private const DEFAULT_LIBRARY_NAME_WINDOWS = 'libhs.dll';

    // Config key for library path
    private const CONFIG_LIBRARY_PATH_KEY = 'vectorscan.library_path';

    /** @var FFI */
    private FFI $ffi;

    /** @var \FFI\CData Pointer to hs_database_t */
    private $db;

    /** @var \FFI\CData Pointer to hs_scratch_t */
    private $scratch;

    /** @var array<int, string> */
    private array $patterns;

    /**
     * Constructor.
     *
     * @param array<int, string> $patterns An array of regex pattern strings.
     * @throws \RuntimeException if libvectorscan is not found or compilation fails.
     */
    public function __construct(array $patterns)
    {
        // Ensure patterns array is numerically indexed starting from 0
        $this->patterns = array_values($patterns);
        $this->loadVectorscanLibrary();
        $this->compilePatterns();
    }

    /**
     * Get the patterns used by this matcher.
     * 
     * @return array<int, string>
     */
    public function getPatterns(): array
    {
        return $this->patterns;
    }

    /**
     * Locate and load the libvectorscan shared library.
     *
     * Uses Laravel configuration (vectorscan.library_path) if available;
     * otherwise, chooses a default based on PHP_OS_FAMILY.
     *
     * @return void
     * @throws \RuntimeException if the library cannot be found.
     */
    private function loadVectorscanLibrary(): void
    {
        // First try to get the library path from config
        $libraryPath = Config::get(self::CONFIG_LIBRARY_PATH_KEY);

        // If no config found, use OS-specific default name
        if (!$libraryPath) {
            $libraryPath = match (PHP_OS_FAMILY) {
                'Windows' => self::DEFAULT_LIBRARY_NAME_WINDOWS,
                'Darwin' => self::DEFAULT_LIBRARY_NAME_DARWIN,
                default => self::DEFAULT_LIBRARY_NAME_LINUX,
            };
        }

        // Search for the library file
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
            // Use try-catch to provide better error messages if FFI loading fails
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

    /**
     * Compile the provided patterns into a libvectorscan database and allocate scratch.
     *
     * @return void
     * @throws \RuntimeException if compilation or scratch allocation fails.
     */
    private function compilePatterns(): void
    {
        Log::debug('Starting vectorscan pattern compilation.');
        $count = count($this->patterns);
        if ($count === 0) {
            Log::warning('Vectorscan compilation attempted with zero patterns.');
        }

        // Allocate C arrays for expressions, flags, and ids
        $exprs = $this->ffi->new("const char*[$count]");
        $flags = $this->ffi->new("unsigned int[$count]");
        $ids = $this->ffi->new("unsigned int[$count]");

        // Prepare patterns for C FFI
        foreach ($this->patterns as $i => $pattern) {
            Log::debug("Processing pattern #{$i}: {$pattern}");
            $len = strlen($pattern);
            $cPattern = $this->ffi->new("char[" . ($len + 1) . "]", false);
            FFI::memcpy($cPattern, $pattern, $len);
            $cPattern[$len] = "\0";

            $exprs[$i] = $cPattern;
            $flags[$i] = self::HS_FLAG_SINGLEMATCH;
            $ids[$i] = $i;
            Log::debug("Pattern #{$i} prepared for compilation.");
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
            // Check if the error pointer is not null before accessing members
            if ($compileError !== null) {
                // Access struct members using ->
                if ($compileError->message !== null) {
                    $errorMessage = FFI::string($compileError->message);
                }
                // The expression field indicates the index of the pattern that failed
                $patternIndex = $compileError->expression; // Directly access the int value

                $this->ffi->{"hs_free_compile_error"}($compileError);
            }
            $logMessage = "libvectorscan compilation failed with error code: {$ret}.";
            if ($patternIndex >= 0 && $patternIndex < $count) {
                $logMessage .= " Error near pattern #{$patternIndex}: '{$this->patterns[$patternIndex]}'.";
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

    /**
     * Scan the given data string and return an array of VectorScanMatch objects.
     *
     * Each match object contains the pattern id, start offset, end offset, flags,
     * and the matching substring.
     *
     * @param string $data The data to scan.
     * @return array<int, MultiPatternMatch>
     * @throws \RuntimeException if scanning fails.
     */
    public function scan(string $data): array
    {
        if (!isset($this->db) || !isset($this->scratch)) {
            throw new \RuntimeException("Vectorscan database or scratch space not initialized.");
        }

        $matches = [];

        $callback = function (int $id, int $from, int $to, int $flags, $context) use (&$matches, $data): int {
            $matchedSubstring = substr($data, $from, $to - $from);
            $originalPattern = $this->patterns[$id] ?? 'unknown pattern';
            $matches[] = new MultiPatternMatch(
                id: $id,
                from: $from,
                to: $to,
                flags: $flags,
                matchedSubstring: $matchedSubstring,
                originalPattern: $originalPattern
            );
            return 0;
        };

        $callbackType = $this->ffi->type("match_event_handler");
        $cCallback = $this->ffi->cast($callbackType, $callback);

        $ret = $this->ffi->{"hs_scan"}(
            $this->db,
            $data,
            strlen($data),
            0,
            $this->scratch,
            $cCallback,
            NULL
        );

        if ($ret < 0) {
            Log::error("libvectorscan hs_scan failed with error code: {$ret}");
            throw new \RuntimeException("libvectorscan hs_scan failed with error code: {$ret}");
        }

        return $matches;
    }

    /**
     * Destructor to free allocated libvectorscan resources.
     */
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
