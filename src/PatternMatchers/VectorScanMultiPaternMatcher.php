<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Lib\Inspectors\PatternMatchers;

use FFI;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

final class VectorScanMultiPaternMatcher
{
    // Vectorscan (libvectorscan) constants.
    private const HS_FLAG_SINGLEMATCH = 0x01;

    private const HS_MODE_BLOCK = 0;

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
     * @param  array<int, string>  $patterns  An array of regex pattern strings.
     *
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
     * @throws \RuntimeException if the library cannot be found.
     */
    private function loadVectorscanLibrary(): void
    {
        $libraryPath = Config::get('vectorscan.library_path');
        if (! $libraryPath) {
            switch (PHP_OS_FAMILY) {
                case 'Windows':
                    $libraryPath = 'vectorscan.dll';
                    break;
                case 'Darwin':
                    $libraryPath = 'libvectorscan.dylib';
                    break;
                default:
                    $libraryPath = 'libvectorscan.so';
                    break;
            }
        }

        if (! file_exists($libraryPath)) {
            $fallbackPaths = [
                $libraryPath,
                '/usr/local/lib/'.$libraryPath,
                '/usr/lib/'.$libraryPath,
            ];
            $found = false;
            foreach ($fallbackPaths as $path) {
                if (file_exists($path)) {
                    $libraryPath = $path;
                    $found = true;
                    break;
                }
            }
            if (! $found) {
                Log::error('libvectorscan library not found. Checked config and fallback paths.');
                throw new \RuntimeException('libvectorscan shared library not found.');
            }
        }

        Log::info("Loading libvectorscan library from: {$libraryPath}");

        $cdef = <<<'CDEF'
            typedef int hs_error_t;
            typedef struct hs_database hs_database_t;
            typedef struct hs_scratch hs_scratch_t;
            typedef struct hs_compile_error hs_compile_error_t; // Added for error handling
            typedef int (*match_event_handler)(unsigned int id, unsigned long long from,
                                               unsigned long long to, unsigned int flags, void *context);
            hs_error_t hs_compile_multi(const char *const *expressions,
                                        const unsigned int *flags,
                                        const unsigned int *ids,
                                        unsigned int elements,
                                        unsigned int mode,
                                        const void *platform,
                                        hs_database_t **db,
                                        hs_compile_error_t **error); // Changed error type
            hs_error_t hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch);
            hs_error_t hs_scan(const hs_database_t *db, const char *data,
                               unsigned int length, unsigned int flags,
                               hs_scratch_t *scratch, match_event_handler onEvent,
                               void *context);
            void hs_free_database(hs_database_t *db);
            void hs_free_scratch(hs_scratch_t *scratch);
            hs_error_t hs_free_compile_error(hs_compile_error_t *error); // Added function to free error
        CDEF;

        $this->ffi = FFI::cdef($cdef, $libraryPath);
    }

    /**
     * Compile the provided patterns into a libvectorscan database and allocate scratch.
     *
     * @throws \RuntimeException if compilation or scratch allocation fails.
     */
    private function compilePatterns(): void
    {
        $count = count($this->patterns);
        if ($count === 0) {
            Log::warning('Vectorscan compilation attempted with zero patterns.');
        }

        $exprs = $this->ffi->new("const char*[$count]");
        $flags = $this->ffi->new("unsigned int[$count]");
        $ids = $this->ffi->new("unsigned int[$count]");

        foreach ($this->patterns as $i => $pattern) {
            $cPattern = $this->ffi->new('char['.(strlen($pattern) + 1).']', false);
            FFI::memcpy($cPattern, $pattern, strlen($pattern) + 1);
            $exprs[$i] = $cPattern;
            $flags[$i] = self::HS_FLAG_SINGLEMATCH;
            $ids[$i] = $i;
        }

        $dbPtr = $this->ffi->new('hs_database_t*[1]');
        $errorPtr = $this->ffi->new('hs_compile_error_t*[1]');

        $ret = $this->ffi->{'hs_compile_multi'}(
            $exprs,
            $flags,
            $ids,
            $count,
            self::HS_MODE_BLOCK,
            null,
            FFI::addr($dbPtr[0]),
            FFI::addr($errorPtr[0])
        );

        if ($ret !== 0) {
            $compileError = $errorPtr[0];
            $errorMessage = 'Unknown compilation error';
            if ($compileError !== null && isset($compileError->message)) {
                $errorMessage = FFI::string($compileError->message);
            }
            Log::error("libvectorscan compilation failed with error code: {$ret}. Message: {$errorMessage}");
            if ($compileError !== null) {
                $this->ffi->{'hs_free_compile_error'}($compileError);
            }
            throw new \RuntimeException("libvectorscan compilation failed: {$errorMessage} (Code: {$ret})");
        }

        $this->db = $dbPtr[0];

        $scratchPtr = $this->ffi->new('hs_scratch_t*[1]');
        $ret = $this->ffi->{'hs_alloc_scratch'}($this->db, FFI::addr($scratchPtr[0]));
        if ($ret !== 0) {
            $this->ffi->{'hs_free_database'}($this->db);
            Log::error("Failed to allocate libvectorscan scratch with error code: {$ret}");
            throw new \RuntimeException("Failed to allocate libvectorscan scratch with error code: {$ret}");
        }
        $this->scratch = $scratchPtr[0];
    }

    /**
     * Scan the given data string and return a Collection of VectorScanMatch objects.
     *
     * Each match object contains the pattern id, start offset, end offset, flags,
     * and the matching substring.
     *
     * @param  string  $data  The data to scan.
     * @return \Illuminate\Support\Collection|MultiPatternMatch[]
     *
     * @throws \RuntimeException if scanning fails.
     */
    public function scan(string $data): Collection
    {
        if (! isset($this->db) || ! isset($this->scratch)) {
            throw new \RuntimeException('Vectorscan database or scratch space not initialized.');
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

        // Create a C type for the callback using CData instead of FFI::callback
        $callbackType = $this->ffi->type('match_event_handler');
        $cCallback = $this->ffi->cast($callbackType, $callback);

        $ret = $this->ffi->{'hs_scan'}(
            $this->db,
            $data,
            strlen($data),
            0,
            $this->scratch,
            $cCallback,
            null
        );

        if ($ret < 0) {
            Log::error("libvectorscan hs_scan failed with error code: {$ret}");
            throw new \RuntimeException("libvectorscan hs_scan failed with error code: {$ret}");
        }

        return new Collection($matches);
    }

    /**
     * Destructor to free allocated libvectorscan resources.
     */
    public function __destruct()
    {
        if (isset($this->scratch)) {
            $this->ffi->{'hs_free_scratch'}($this->scratch);
        }
        if (isset($this->db)) {
            $this->ffi->{'hs_free_database'}($this->db);
        }
    }
}
