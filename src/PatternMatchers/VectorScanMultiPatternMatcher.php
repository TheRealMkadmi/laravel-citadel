<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\PatternMatchers;

use FFI;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\File;

final class VectorScanMultiPatternMatcher extends AbstractMultiPatternMatcher
{
    private const HS_SUCCESS = 0;

    private const HS_INVALID = -1;

    private const HS_NOMEM = -2;

    private const HS_SCAN_TERMINATED = -3;

    private const HS_COMPILER_ERROR = -4;

    private const HS_DB_VERSION_ERROR = -5;

    private const HS_DB_PLATFORM_ERROR = -6;

    private const HS_DB_MODE_ERROR = -7;

    private const HS_BAD_ALIGN = -8;

    private const HS_BAD_ALLOC = -9;

    private const HS_FLAG_CASELESS = 1;

    private const HS_FLAG_DOTALL = 2;

    private const HS_FLAG_MULTILINE = 4;

    private const HS_FLAG_SINGLEMATCH = 8;

    private const HS_FLAG_ALLOWEMPTY = 16;

    private const HS_FLAG_UTF8 = 32;

    private const HS_FLAG_UCP = 64;

    private const HS_FLAG_PREFILTER = 128;

    private const HS_FLAG_SOM_LEFTMOST = 256;

    private const HS_FLAG_NONE = 0;

    private const HS_MODE_BLOCK = 1;

    private const HS_MODE_STREAM = 2;

    private const HS_MODE_VECTORED = 4;

    private const DEFAULT_LIBRARY_NAME_LINUX = 'libhs.so.5';

    private const DEFAULT_LIBRARY_NAME_DARWIN = 'libhs.dylib';

    private const DEFAULT_LIBRARY_NAME_WINDOWS = 'libhs.dll';

    private const CONFIG_LIBRARY_PATH_KEY = 'vectorscan.library_path';

    private const CONFIG_DB_PATH_KEY = 'citadel.pattern_matcher.serialized_db_path';

    private const HS_CALLBACK_CONTINUE = 0;

    private const HS_SCAN_FLAG_NONE = 0;

    private FFI $ffi;

    private $db;

    private $scratch;

    /**
     * Create a new VectorScan pattern matcher instance.
     * 
     * @param array $patterns Array of patterns to compile (if not loading from serialized database)
     * @param string|null $serializedDbPath Optional path to serialized database
     */
    public function __construct(array $patterns, ?string $serializedDbPath = null)
    {
        $this->patterns = $patterns;
        $this->loadVectorscanLibrary();
        
        // Try to load serialized database if path is provided or configured
        $dbPath = $serializedDbPath ?? config(self::CONFIG_DB_PATH_KEY);
        
        if ($dbPath && file_exists($dbPath)) {
            $loaded = $this->loadDatabase($dbPath);
            if (!$loaded) {
                // Fall back to compilation
                $this->compilePatterns();
            }
        } else {
            // No database file available, compile patterns
            $this->compilePatterns();
        }
        
        $this->allocateScratch();
    }

    private function loadVectorscanLibrary(): void
    {
        $libraryPath = Config::get(self::CONFIG_LIBRARY_PATH_KEY);

        if (! $libraryPath) {
            $libraryPath = match (PHP_OS_FAMILY) {
                'Windows' => self::DEFAULT_LIBRARY_NAME_WINDOWS,
                'Darwin' => self::DEFAULT_LIBRARY_NAME_DARWIN,
                default => self::DEFAULT_LIBRARY_NAME_LINUX,
            };
        }

        $searchPaths = [
            $libraryPath,
            '/usr/lib/x86_64-linux-gnu/'.basename($libraryPath),
            '/lib/'.basename($libraryPath),
            '/usr/local/lib/'.basename($libraryPath),
            '/usr/lib/'.basename($libraryPath),
        ];

        $foundPath = null;
        foreach ($searchPaths as $path) {
            if (file_exists($path)) {
                $foundPath = $path;
                break;
            }
        }

        if (! $foundPath) {
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

// Serialization functions
hs_error_t hs_serialize_database(const hs_database_t *db, char **bytes, size_t *length);
hs_error_t hs_deserialize_database(const char *bytes, size_t length, hs_database_t **db);
hs_error_t hs_serialized_database_size(const char *bytes, size_t length, size_t *deserialized_size);
hs_error_t hs_serialized_database_info(const char *bytes, size_t length, char **info);

// Standard C memory free function
void free(void *ptr);
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
            $cPattern = $this->ffi->new('char['.($len + 1).']', false);
            FFI::memcpy($cPattern, $pattern, $len);
            $cPattern[$len] = "\0";

            $exprs[$i] = $cPattern;
            $flags[$i] = self::HS_FLAG_SINGLEMATCH | self::HS_FLAG_DOTALL;
            $ids[$i] = $i;
        }

        $dbPtr = $this->ffi->new('hs_database_t*[1]');
        $errorPtr = $this->ffi->new('hs_compile_error_t*[1]');

        Log::debug("Calling hs_compile_multi with {$count} patterns. Mode: ".self::HS_MODE_BLOCK);
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

        if ($ret !== self::HS_SUCCESS) {
            $compileError = $errorPtr[0];
            $errorMessage = 'Unknown compilation error';
            $patternIndex = -1;

            if ($compileError !== null) {
                if ($compileError->message !== null) {
                    $errorMessage = FFI::string($compileError->message);
                }
                $patternIndex = $compileError->expression;
                $this->ffi->{'hs_free_compile_error'}($compileError);
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
        Log::info('libvectorscan patterns compiled successfully. Database pointer: '.($this->db ? 'valid' : 'invalid'));
    }

    private function allocateScratch(): void
    {
        // Ensure database is valid before allocating scratch
        if (!isset($this->db)) {
            Log::error("Cannot allocate scratch space: Database is not initialized.");
            throw new \RuntimeException("Cannot allocate scratch space: Database is not initialized.");
        }

        $scratchPtr = $this->ffi->new('hs_scratch_t*[1]');
        Log::debug('Allocating vectorscan scratch space.');
        $ret = $this->ffi->{'hs_alloc_scratch'}($this->db, FFI::addr($scratchPtr[0]));
        if ($ret !== self::HS_SUCCESS) {
            Log::error("Failed to allocate libvectorscan scratch space with error code: {$ret}");
            throw new \RuntimeException("Failed to allocate libvectorscan scratch space with error code: {$ret}");
        }
        $this->scratch = $scratchPtr[0];
        Log::info('libvectorscan scratch space allocated successfully. Scratch pointer: '.($this->scratch ? 'valid' : 'invalid'));
        Log::debug('Finished vectorscan scratch allocation.');
    }

    /**
     * Load a serialized database from a file.
     *
     * @param string $dbPath Path to the serialized database file
     * @return bool True if database was loaded successfully, false otherwise
     */
    private function loadDatabase(string $dbPath): bool
    {
        Log::debug("Attempting to load serialized database from path: {$dbPath}");

        try {
            if (!file_exists($dbPath)) {
                Log::error("Serialized database file not found: {$dbPath}");
                return false;
            }

            // Read the file as binary data to ensure accurate byte representation
            $serializedData = file_get_contents($dbPath);
            if ($serializedData === false) {
                Log::error("Failed to read serialized database file: {$dbPath}");
                return false;
            }

            $dataLength = strlen($serializedData);
            Log::debug("Loaded serialized database from file, size: {$dataLength} bytes");

            // First get info about the database to log - create local data buffer to avoid memory issues
            $tempData = $this->ffi->new("char[$dataLength]");
            FFI::memcpy($tempData, $serializedData, $dataLength);

            // Get database info before deserializing
            $infoPtr = $this->ffi->new('char*[1]');
            $infoResult = $this->ffi->{'hs_serialized_database_info'}(
                $tempData, 
                $dataLength, 
                FFI::addr($infoPtr[0])
            );
            
            if ($infoResult === self::HS_SUCCESS) {
                $info = FFI::string($infoPtr[0]);
                Log::info("Serialized database info: {$info}");
                
                // Use the standard C free function as per Hyperscan documentation
                // This memory was allocated by Hyperscan's internal allocator
                Log::debug("Freeing database info string pointer");
                $this->ffi->free($infoPtr[0]); 
            }

            // Create database pointer for deserialization result
            $dbPtr = $this->ffi->new('hs_database_t*[1]');
            
            // Create new buffer for deserialization that will remain valid for the call
            // We need to ensure this buffer stays in scope during the entire deserialization
            $deserializeBuffer = $this->ffi->new("char[$dataLength]");
            FFI::memcpy($deserializeBuffer, $serializedData, $dataLength);

            Log::debug("Calling hs_deserialize_database with data length: {$dataLength}");
            $ret = $this->ffi->{'hs_deserialize_database'}(
                $deserializeBuffer, 
                $dataLength, 
                FFI::addr($dbPtr[0])
            );

            if ($ret !== self::HS_SUCCESS) {
                $errorMessage = match ($ret) {
                    self::HS_DB_VERSION_ERROR => "Database version mismatch",
                    self::HS_DB_PLATFORM_ERROR => "Database platform mismatch",
                    self::HS_DB_MODE_ERROR => "Database mode mismatch",
                    self::HS_NOMEM => "Insufficient memory",
                    default => "Error code: {$ret}",
                };
                Log::error("Failed to deserialize database: {$errorMessage}");
                return false;
            }

            // Free any existing database and scratch before assigning new ones
            if (isset($this->db)) {
                Log::debug("Freeing existing database pointer");
                $this->ffi->{'hs_free_database'}($this->db);
                $this->db = null;
            }
            
            if (isset($this->scratch)) {
                Log::debug("Freeing existing scratch space pointer");
                $this->ffi->{'hs_free_scratch'}($this->scratch);
                $this->scratch = null;
            }

            // Store the newly created database pointer
            $this->db = $dbPtr[0];
            Log::info("Successfully loaded serialized database from path: {$dbPath}");

            // Re-allocate scratch space for the new database
            try {
                $this->allocateScratch();
                return true;
            } catch (\RuntimeException $e) {
                Log::error("Failed to allocate scratch for deserialized database: {$e->getMessage()}");
                
                // Clean up the database if scratch allocation fails
                if (isset($this->db)) {
                    $this->ffi->{'hs_free_database'}($this->db);
                    $this->db = null;
                }
                return false;
            }
        } catch (\Throwable $e) {
            Log::error("Exception during database deserialization: {$e->getMessage()}", [
                'exception' => $e,
                'trace' => $e->getTraceAsString()
            ]);
            
            // Make sure to clean up any partially initialized resources
            if (isset($dbPtr) && isset($dbPtr[0]) && !isset($this->db)) {
                $this->ffi->{'hs_free_database'}($dbPtr[0]);
            }
            return false;
        }
    }

    public function scan(string $data): array
    {
        Log::debug('scan() called with data length: '.strlen($data));

        if (! isset($this->db) || ! isset($this->scratch)) {
            Log::error('Attempted scan with uninitialized database or scratch space. DB: '.(isset($this->db) ? 'set' : 'null').
                       ', Scratch: '.(isset($this->scratch) ? 'set' : 'null'));
            throw new \RuntimeException('Vectorscan database or scratch space not initialized.');
        }

        if (empty($data)) {
            Log::debug('Skipping scan for empty data.');

            return []; // Avoid scanning empty data
        }

        $matchesFound = [];
        Log::debug('Preparing callback for hs_scan. Data length: '.strlen($data).", Data preview: '".
                  (strlen($data) > 50 ? substr($data, 0, 50).'...' : $data)."'");

        $callbackClosure = function ($id, $fromRaw, $toRaw, int $flags, $context) use (&$matchesFound, $data): int {
            Log::debug("Full data => {$data}");
            Log::debug("Vectorscan match callback fired: id={$id}, from={$fromRaw}, to={$toRaw}, flags={$flags}");

            if (! isset($this->patterns[$id])) {
                Log::warning("Callback received invalid pattern ID: {$id}, max valid ID: ".(count($this->patterns) - 1));

                return self::HS_CALLBACK_CONTINUE;
            }

            $fromInt = (int) $fromRaw;
            $toInt = (int) $toRaw;

            if ($fromInt < 0 || $toInt < $fromInt || $toInt > strlen($data)) {
                Log::error("Invalid match offsets: from={$fromInt}, to={$toInt}, data_len=".strlen($data));

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

        Log::debug('Calling hs_scan function with database pointer: '.($this->db ? 'valid' : 'invalid').
                  ' and scratch pointer: '.($this->scratch ? 'valid' : 'invalid'));
        $ret = $this->ffi->{'hs_scan'}(
            $this->db,
            $data,
            strlen($data),
            self::HS_SCAN_FLAG_NONE,
            $this->scratch,
            $callbackClosure,
            null
        );

        if ($ret < self::HS_SUCCESS && $ret !== self::HS_SCAN_TERMINATED) {
            Log::error("libvectorscan hs_scan failed with error code: {$ret}, HS_SUCCESS={".self::HS_SUCCESS.
                      '}, HS_SCAN_TERMINATED={'.self::HS_SCAN_TERMINATED.'}');
            throw new \RuntimeException("libvectorscan hs_scan failed with error code: {$ret}");
        }

        Log::info("libvectorscan hs_scan completed with return code: {$ret}. Found ".count($matchesFound).' matches.');

        foreach ($matchesFound as $index => $match) {
            Log::debug("Match #{$index}: ID={$match->id}, from={$match->from}, to={$match->to}, flags={$match->flags}, matchedSubstring='{$match->matchedSubstring}'");
        }

        Log::debug('Scan complete. Returning '.count($matchesFound).' matches.');

        return $matchesFound;
    }

    /**
     * Serialize and persist the database to a file.
     *
     * @param string $filePath Path where to save the serialized database
     * @return bool True if serialization was successful, false otherwise
     */
    public function serializeDatabase(string $filePath): bool
    {
        if (!isset($this->db)) {
            Log::error('Cannot serialize database: Database not initialized');
            return false;
        }

        try {
            // Create pointers for serialization output
            $bytesPtr = $this->ffi->new('char*[1]');
            $lengthPtr = $this->ffi->new('size_t[1]');
            
            Log::debug("Calling hs_serialize_database");
            $ret = $this->ffi->{'hs_serialize_database'}(
                $this->db,
                FFI::addr($bytesPtr[0]),
                FFI::addr($lengthPtr[0])
            );
            
            if ($ret !== self::HS_SUCCESS) {
                Log::error("Database serialization failed with error code: {$ret}");
                return false;
            }
            
            // Get the serialized data
            $length = $lengthPtr[0];
            $bytes = $bytesPtr[0];
            
            Log::debug("Database serialized successfully, size: {$length} bytes");
            
            // Copy the serialized data to a PHP string before freeing the C memory
            $serializedData = FFI::string($bytes, $length);
            
            // Free the memory allocated by hs_serialize_database using the C free function
            // As per Hyperscan documentation, this memory was allocated by Hyperscan's internal allocator
            Log::debug("Freeing serialized database buffer pointer");
            $this->ffi->free($bytes);
            
            // Ensure the output directory exists
            $directory = dirname($filePath);
            if (!is_dir($directory)) {
                Log::debug("Creating directory: {$directory}");
                if (!File::makeDirectory($directory, 0755, true)) {
                    Log::error("Failed to create directory: {$directory}");
                    return false;
                }
            }
            
            // Write the serialized data to file with exclusive lock
            Log::debug("Writing serialized database to file: {$filePath}");
            $bytesWritten = file_put_contents($filePath, $serializedData, LOCK_EX);
            
            if ($bytesWritten === false || $bytesWritten !== $length) {
                Log::error("Failed to write serialized database to {$filePath}. Expected {$length} bytes, wrote {$bytesWritten}");
                return false;
            }
            
            Log::info("Successfully serialized database to {$filePath} ({$bytesWritten} bytes)");
            return true;
        } catch (\Throwable $e) {
            Log::error("Exception during database serialization: {$e->getMessage()}", [
                'exception' => $e,
                'trace' => $e->getTraceAsString()
            ]);
            return false;
        }
    }

    /**
     * Get information about a serialized database file
     * 
     * @param string $filePath Path to the serialized database file
     * @return string|null Database information string or null on error
     */
    public function getSerializedDatabaseInfo(string $filePath): ?string
    {
        if (!file_exists($filePath)) {
            Log::error("Serialized database file not found: {$filePath}");
            return null;
        }
        
        try {
            $serializedData = file_get_contents($filePath);
            if ($serializedData === false) {
                Log::error("Failed to read serialized database file: {$filePath}");
                return null;
            }
            
            $dataLength = strlen($serializedData);
            Log::debug("Reading info from serialized database, size: {$dataLength} bytes");
            
            // Create a buffer with the serialized data that will remain valid for the function call
            $dataBuffer = $this->ffi->new("char[$dataLength]");
            FFI::memcpy($dataBuffer, $serializedData, $dataLength);
            
            // Get database info
            $infoPtr = $this->ffi->new('char*[1]');
            Log::debug("Calling hs_serialized_database_info");
            $ret = $this->ffi->{'hs_serialized_database_info'}(
                $dataBuffer,
                $dataLength,
                FFI::addr($infoPtr[0])
            );
            
            if ($ret !== self::HS_SUCCESS) {
                Log::error("Failed to get database info with error code: {$ret}");
                return null;
            }
            
            // Copy info to PHP string before freeing the C memory
            $info = FFI::string($infoPtr[0]);
            Log::debug("Retrieved database info: {$info}");
            
            // Free the memory allocated by hs_serialized_database_info using C free function
            // Per Hyperscan documentation, this memory was allocated by Hyperscan's internal allocator
            Log::debug("Freeing database info string pointer");
            $this->ffi->free($infoPtr[0]);
            
            return $info;
        } catch (\Throwable $e) {
            Log::error("Exception while getting database info: {$e->getMessage()}", [
                'exception' => $e,
                'trace' => $e->getTraceAsString()
            ]);
            return null;
        }
    }

    public function __destruct()
    {
        try {
            if (isset($this->scratch)) {
                Log::debug('Freeing scratch space pointer in destructor');
                $this->ffi->{'hs_free_scratch'}($this->scratch);
                $this->scratch = null;
            }
            
            if (isset($this->db)) {
                Log::debug('Freeing database pointer in destructor');
                $this->ffi->{'hs_free_database'}($this->db);
                $this->db = null;
            }
        } catch (\Throwable $e) {
            // Just log in destructor, never throw
            Log::error("Exception during VectorScanMultiPatternMatcher destruction: {$e->getMessage()}");
        }
    }
}
