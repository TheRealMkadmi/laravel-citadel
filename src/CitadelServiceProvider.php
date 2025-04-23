<?php

namespace TheRealMkadmi\Citadel;

use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Laravel\Octane\Contracts\Server;
use Reefki\DeviceDetector\DeviceDetector;
use Spatie\LaravelPackageTools\Commands\InstallCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Symfony\Component\Finder\Finder;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\Commands\CitadelBanCommand;
use TheRealMkadmi\Citadel\Commands\CitadelCompileRegexCommand;
use TheRealMkadmi\Citadel\Commands\CitadelUnbanCommand;
use TheRealMkadmi\Citadel\Components\Fingerprint;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\DataStore\OctaneDataStore;
use TheRealMkadmi\Citadel\DataStore\RedisDataStore;
use TheRealMkadmi\Citadel\Http\Controllers\CitadelApiController;
use TheRealMkadmi\Citadel\Middleware\ApiAuthMiddleware;
use TheRealMkadmi\Citadel\Middleware\BanMiddleware;
use TheRealMkadmi\Citadel\Middleware\GeofenceMiddleware;
use TheRealMkadmi\Citadel\Middleware\ProtectRouteMiddleware;
use TheRealMkadmi\Citadel\PatternMatchers\MultiPatternMatcher;
use TheRealMkadmi\Citadel\PatternMatchers\PcreMultiPatternMatcher;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;

class CitadelServiceProvider extends PackageServiceProvider
{
    /**
     * Config keys
     */
    private const CONFIG_CACHE_KEY = 'citadel.cache';

    private const CONFIG_API_KEY = 'citadel.api';

    private const CONFIG_MIDDLEWARE_KEY = 'citadel.middleware';

    private const CONFIG_PATTERN_MATCHER_KEY = 'citadel.pattern_matcher';

    private const CONFIG_VECTORSCAN_KEY = 'citadel.vectorscan';

    /**
     * Route names
     */
    public const ROUTE_NAME_BAN = 'citadel.api.ban';

    public const ROUTE_NAME_UNBAN = 'citadel.api.unban';

    public const ROUTE_NAME_STATUS = 'citadel.api.status';

    /**
     * Pattern file constants
     */
    private const PATTERN_COMMENT_PREFIX = '#';

    /**
     * Middleware group names
     */
    private const MIDDLEWARE_GROUP_PROTECT = 'citadel-protect';

    private const MIDDLEWARE_GROUP_ACTIVE = 'citadel-active';

    private const MIDDLEWARE_ALIAS_API_AUTH = 'citadel-api-auth';

    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('laravel-citadel')
            ->hasRoute('api')
            ->hasConfigFile()
            ->hasConfigFile('ip-tree')
            ->hasViews()
            ->hasViewComponents('citadel', Fingerprint::class)
            ->hasAssets()
            ->hasInstallCommand(function (InstallCommand $command) {
                $command
                    ->startWith(function (InstallCommand $command) {
                        $command->info('Installing Laravel Citadel...');
                    })
                    ->publishConfigFile()
                    ->copyAndRegisterServiceProviderInApp()
                    ->publishAssets()
                    ->askToStarRepoOnGitHub('therealmkadmi/laravel-citadel')
                    ->endWith(function (InstallCommand $command) {
                        $command->info('Laravel Citadel has been installed successfully!');
                        $command->info('You can now use the Citadel fingerprinting in your application.');
                        $command->info('Add the fingerprint script to your layout using either:');
                        $command->info('  1. @fingerprintScript directive');
                        $command->info('  2. <x-citadel::fingerprint /> component');
                    });
            });

        // Publish the pattern files
        $this->publishes([
            __DIR__.'/../resources/payload-inspection-patterns.list' => resource_path('vendor/citadel/payload-inspection-patterns.list'),
        ], 'citadel-patterns');
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function packageBooted()
    {
        // Register the getFingerprint macro on the Request class
        Request::macro('getFingerprint', fn () => app(Citadel::class)->getFingerprint($this));

        // Register middleware
        $router = $this->app->make(Router::class);

        $router->middlewareGroup(self::MIDDLEWARE_GROUP_ACTIVE, [
            ProtectRouteMiddleware::class,
            GeofenceMiddleware::class,
            BanMiddleware::class,
        ]);

        $router->middlewareGroup(self::MIDDLEWARE_GROUP_PROTECT, [
            ProtectRouteMiddleware::class,
            BanMiddleware::class,
        ]);

        $router->aliasMiddleware(self::MIDDLEWARE_ALIAS_API_AUTH, ApiAuthMiddleware::class);

        // Register event listener for BlacklistUpdated
        \Illuminate\Support\Facades\Event::listen(
            \TheRealMkadmi\Citadel\Events\BlacklistUpdated::class,
            \TheRealMkadmi\Citadel\Listeners\HandleBlacklistUpdate::class
        );

        $this->loadRoutesFrom(__DIR__.'/../routes/api.php');
        $this->commands([
            CitadelBanCommand::class,
            CitadelUnbanCommand::class,
            CitadelCompileRegexCommand::class,
        ]);

    }

    /**
     * Register any package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/citadel.php', 'citadel');
        $this->mergeConfigFrom(__DIR__.'/../config/ip-tree.php', 'ip-tree');

        // Register the DeviceDetector service
        $this->app->singleton(DeviceDetector::class, function ($app) {
            return new DeviceDetector($app->make(CacheRepository::class));
        });

        // Register the DataStore singleton first since other components depend on it
        $this->registerDataStore();

        // Register the pattern matcher service
        $this->registerPatternMatcher();

        // Register the main Citadel service
        $this->app->singleton(Citadel::class, fn ($app) => new Citadel($app->make(DataStore::class), $app->make(\TheRealMkadmi\Citadel\IpTree\IpTree::class),
                $app['events'],
                config('ip-tree.broadcast_channel', 'citadel-blacklist')));

        // Register IpTree based on config
        $this->app->singleton(\TheRealMkadmi\Citadel\IpTree\IpTree::class, function ($app) {
            $driver = config('ip-tree.driver', 'redis');
            $channel = config('ip-tree.broadcast_channel', 'citadel-blacklist');
            if ($driver === 'ffi') {
                $libPath = config_path('citadel/libpatricia.so');
                return new \TheRealMkadmi\Citadel\IpTree\FfiIpTree($libPath, $channel);
            }
            // Default: redis
            $redis = $app['redis']->connection();
            $setKey = 'citadel:ips';
            return new \TheRealMkadmi\Citadel\IpTree\RedisIpTree($redis, $setKey, $channel);
        });

        $this->app->alias(\TheRealMkadmi\Citadel\Citadel::class, 'citadel');

        // Register analyzers and middleware
        $this->registerAnalyzers();
        $this->registerMiddleware();

        // Register API controller
        $this->app->singleton(CitadelApiController::class, fn ($app) => new CitadelApiController($app->make(DataStore::class)));
    }

    protected function registerDataStore()
    {
        $this->app->singleton(DataStore::class, function ($app) {
            $driver = config(self::CONFIG_CACHE_KEY.'.driver', 'auto');

            // If a specific driver is configured, use it directly
            if ($driver !== 'auto') {
                return $this->resolveDataStoreByDriver($driver);
            }

            // Auto-detect the best available driver
            return $this->resolveAutoDataStore($app);
        });
    }

    protected function resolveAutoDataStore($app): DataStore
    {
        // Get preference configuration
        $preferOctane = config(self::CONFIG_CACHE_KEY.'.prefer_octane', true);
        $preferRedis = config(self::CONFIG_CACHE_KEY.'.prefer_redis', true);

        // If Octane is available and preferred, use Octane store
        if ($preferOctane && $app->bound(Server::class)) {
            return new OctaneDataStore;
        }

        // If Redis is available and preferred, use Redis store
        if ($preferRedis && $this->isRedisAvailable()) {
            return new RedisDataStore;
        }

        // Fall back to array store
        return new ArrayDataStore;
    }

    protected function resolveDataStoreByDriver(string $driver): DataStore
    {
        return match ($driver) {
            RedisDataStore::STORE_IDENTIFIER => new RedisDataStore,
            OctaneDataStore::STORE_IDENTIFIER => new OctaneDataStore,
            default => new ArrayDataStore,
        };
    }

    protected function isRedisAvailable(): bool
    {
        return class_exists('Redis') &&
            config('database.redis.client', null) !== null &&
            ! empty(config('database.redis.default', []));
    }

    protected function registerAnalyzers()
    {
        // Discover all classes that implement IRequestAnalyzer
        $analyzers = $this->discoverAnalyzers();

        // Register each analyzer with DataStore dependency automatically injected
        foreach ($analyzers as $analyzer) {
            $this->app->singleton($analyzer);
        }
    }

    /**
     * Register the middleware with its dependencies.
     *
     * @return void
     */
    protected function registerMiddleware()
    {
        // Register the BanMiddleware
        $this->app->singleton(BanMiddleware::class, function ($app) {
            return new BanMiddleware($app->make(DataStore::class));
        });

        // Register GeofenceMiddleware
        $this->app->singleton(GeofenceMiddleware::class);

        // Register middleware with analyzers grouped by type
        $this->app->singleton(ProtectRouteMiddleware::class, function ($app) {
            // Group analyzers by their type
            $analyzers = $this->groupAnalyzersByCapabilities();

            // Create the middleware instance with the appropriate analyzers based on context
            return new ProtectRouteMiddleware(
                $analyzers,
                $app->make(DataStore::class)
            );
        });

        // Register API auth middleware
        $this->app->singleton(ApiAuthMiddleware::class);
    }

    /**
     * Group analyzers by their capabilities
     *
     * @return array<string, array<IRequestAnalyzer>>
     */
    protected function groupAnalyzersByCapabilities(): array
    {
        $analyzerClasses = $this->discoverAnalyzers();

        $bodyAnalyzers = [];
        $externalResourceAnalyzers = [];
        $allAnalyzers = [];

        foreach ($analyzerClasses as $class) {
            /** @var IRequestAnalyzer $analyzer */
            $analyzer = $this->app->make($class);

            if (! $analyzer->isEnabled()) {
                continue;
            }

            // Add to all analyzers collection
            $allAnalyzers[] = $analyzer;

            // Group by specific capabilities
            if ($analyzer->requiresRequestBody()) {
                $bodyAnalyzers[] = $analyzer;
            }

            if ($analyzer->usesExternalResources()) {
                $externalResourceAnalyzers[] = $analyzer;
            }
        }

        return [
            'all' => $allAnalyzers,
            'body_analyzers' => $bodyAnalyzers,
            'external_resource_analyzers' => $externalResourceAnalyzers,
        ];
    }

    /**
     * Discover all request analyzer implementations.
     */
    protected function discoverAnalyzers(): Collection
    {
        $analyzersPath = __DIR__.'/Analyzers';
        $namespace = 'TheRealMkadmi\\Citadel\\Analyzers\\';

        $finder = new Finder;
        $finder->files()->in($analyzersPath)->name('*.php');

        return collect($finder)
            ->map(fn($file) => $namespace . $file->getBasename('.php'))
            ->filter(fn($className) => class_exists($className))
            ->filter(function ($className) {
                $reflection = new \ReflectionClass($className);
                return !$reflection->isInterface() && !$reflection->isAbstract();
            })
            ->filter(fn($className) => in_array(IRequestAnalyzer::class, class_implements($className) ?: []))
            ->values();
    }

    /**
     * Register the pattern matcher service.
     */
    protected function registerPatternMatcher(): void
    {
        $this->app->singleton(MultiPatternMatcher::class, function ($app) {
            Log::debug('Registering pattern matcher service.');

            // Determine implementation based on configuration
            $implementation = config(self::CONFIG_PATTERN_MATCHER_KEY.'.implementation', 'vectorscan');

            // Get patterns file path from config or use package default if not set
            $patternsFile = config(self::CONFIG_PATTERN_MATCHER_KEY.'.patterns_file');

            // If the config value doesn't exist or the file doesn't exist at the specified path,
            // fall back to the package's resource file
            if (empty($patternsFile) || ! file_exists($patternsFile)) {
                $packagePatternsFile = __DIR__.'/../resources/payload-inspection-patterns.list';

                if (file_exists($packagePatternsFile)) {
                    $patternsFile = $packagePatternsFile;
                    Log::info('Using package default patterns file.', ['file' => $patternsFile]);
                } else {
                    Log::emergency("Default patterns file not found: {$packagePatternsFile}");

                    return null;
                }
            } else {
                Log::info('Using configured patterns file.', ['file' => $patternsFile]);
            }

            if (! file_exists($patternsFile)) {
                Log::emergency("Patterns file not found: {$patternsFile}");

                return null;
            }

            $patterns = file($patternsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            Log::debug('Determining pattern matcher implementation.', ['implementation' => $implementation]);

            return match ($implementation) {
                'pcre' => $this->createPcrePatternMatcher($patterns),
                'vectorscan' => $this->createVectorscanPatternMatcher($patterns, $patternsFile),
                default => $this->createVectorscanPatternMatcher($patterns, $patternsFile),
            };
        });

        // Add explicit binding for VectorScanMultiPatternMatcher for direct resolution
        $this->app->bind(VectorScanMultiPatternMatcher::class, function ($app) {
            // Get patterns file path from config
            $patternsFile = config(self::CONFIG_PATTERN_MATCHER_KEY.'.patterns_file');

            if (empty($patternsFile) || ! file_exists($patternsFile)) {
                $packagePatternsFile = __DIR__.'/../resources/payload-inspection-patterns.list';
                if (file_exists($packagePatternsFile)) {
                    $patternsFile = $packagePatternsFile;
                }
            }

            if (! file_exists($patternsFile)) {
                Log::emergency('Patterns file not found for VectorScanMultiPatternMatcher binding');
                throw new \RuntimeException('Patterns file not found for VectorScanMultiPatternMatcher binding');
            }

            $patterns = file($patternsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

            return $this->createVectorscanPatternMatcher($patterns, $patternsFile);
        });
    }

    /**
     * Create a PCRE-based pattern matcher.
     *
     * @param  array<int, string>  $patterns  Array of pattern strings
     */
    protected function createPcrePatternMatcher(array $patterns): MultiPatternMatcher
    {
        // Get PCRE configuration from config
        $pcreConfig = config('citadel.pcre', []);

        // Create and return the PCRE pattern matcher
        return new PcreMultiPatternMatcher($patterns, $pcreConfig);
    }

    /**
     * Create a Vectorscan-based pattern matcher.
     *
     * @param  array<int, string>  $patterns  Array of pattern strings
     * @param  string  $patternsFilePath  Path to the pattern file
     */
    protected function createVectorscanPatternMatcher(array $patterns, string $patternsFilePath): MultiPatternMatcher
    {
        // Get configuration options
        $serializedDbPath = config(self::CONFIG_PATTERN_MATCHER_KEY.'.serialized_db_path');
        $autoSerialize = config(self::CONFIG_PATTERN_MATCHER_KEY.'.auto_serialize', true);
        $useHashValidation = config(self::CONFIG_PATTERN_MATCHER_KEY.'.use_hash_validation', true);

        // Check if serialized file exists and is valid
        $databaseIsValid = false;
        if ($serializedDbPath && file_exists($serializedDbPath)) {
            // Use hash validation if enabled
            if ($useHashValidation) {
                $databaseIsValid = VectorScanMultiPatternMatcher::isDatabaseValid($serializedDbPath, $patternsFilePath);

                if (! $databaseIsValid) {
                    Log::info("Serialized pattern database exists but the pattern file hash doesn't match. Recompiling.");
                }
            } else {
                // If hash validation is disabled, consider any existing database valid
                $databaseIsValid = true;
            }
        }

        // Create VectorScan pattern matcher with patterns and serialized database path if valid
        $matcher = new VectorScanMultiPatternMatcher($patterns, $databaseIsValid ? $serializedDbPath : null);

        // Auto-serialize if enabled and database doesn't exist or is invalid
        if ($autoSerialize && $serializedDbPath && ! $databaseIsValid) {
            $directory = dirname($serializedDbPath);

            // Ensure directory exists
            if (! is_dir($directory)) {
                if (! mkdir($directory, 0755, true)) {
                    Log::error("Failed to create directory for serialized pattern database: {$directory}");
                }
            }

            if (is_writable($directory) || (file_exists($serializedDbPath) && is_writable($serializedDbPath))) {
                Log::info("Auto-serializing pattern database to {$serializedDbPath}");

                // Use the hash-based serialization method
                $result = $matcher->serializeDatabaseWithHash($serializedDbPath, $patternsFilePath);

                if ($result) {
                    Log::info('Successfully serialized pattern database with hash validation');
                } else {
                    Log::error('Failed to serialize pattern database');
                }
            } else {
                Log::error("Cannot serialize pattern database: directory {$directory} is not writable");
            }
        }

        return $matcher;
    }
}
