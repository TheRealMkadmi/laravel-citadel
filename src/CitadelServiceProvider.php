<?php

namespace TheRealMkadmi\Citadel;

use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Route;
use Spatie\LaravelPackageTools\Commands\InstallCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Symfony\Component\Finder\Finder;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\Commands\CitadelBanCommand;
use TheRealMkadmi\Citadel\Commands\CitadelUnbanCommand;
use TheRealMkadmi\Citadel\Components\Fingerprint;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\DataStore\OctaneDataStore;
use TheRealMkadmi\Citadel\DataStore\RedisDataStore;
use TheRealMkadmi\Citadel\Http\Controllers\CitadelApiController;
use TheRealMkadmi\Citadel\Middleware\ApiAuthMiddleware;
use TheRealMkadmi\Citadel\Middleware\BanMiddleware;
use TheRealMkadmi\Citadel\Middleware\GeofenceMiddleware;
use TheRealMkadmi\Citadel\Middleware\PostProtectRouteMiddleware;
use TheRealMkadmi\Citadel\Middleware\ProtectRouteMiddleware;

class CitadelServiceProvider extends PackageServiceProvider
{
    /**
     * Group keys for analyzer types
     */
    private const ANALYZER_GROUP_ACTIVE = 'active';

    private const ANALYZER_GROUP_PASSIVE = 'passive';

    private const ANALYZER_GROUP_PAYLOAD = 'payload_scanners';

    /**
     * Config keys
     */
    private const CONFIG_CACHE_KEY = 'citadel.cache';

    private const CONFIG_API_KEY = 'citadel.api';

    private const CONFIG_MIDDLEWARE_KEY = 'citadel.middleware';

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
            ->hasConfigFile()
            ->hasViews()
            ->hasViewComponents('citadel', Fingerprint::class)
            ->hasAssets()
            ->hasCommand(CitadelBanCommand::class)
            ->hasCommand(CitadelUnbanCommand::class)
            ->hasInstallCommand(function (InstallCommand $command) {
                $command
                    ->startWith(function (InstallCommand $command) {
                        $command->info('Installing Laravel Citadel...');
                    })
                    ->publishConfigFile()
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

        // Register the active middleware group (full protection)
        $router->middlewareGroup(self::MIDDLEWARE_GROUP_ACTIVE, [
            ProtectRouteMiddleware::class,
            PostProtectRouteMiddleware::class,
            GeofenceMiddleware::class,
            BanMiddleware::class,
        ]);

        // Keep the original complete middleware group for backward compatibility
        $router->middlewareGroup(self::MIDDLEWARE_GROUP_PROTECT, [
            ProtectRouteMiddleware::class,
            PostProtectRouteMiddleware::class,
            BanMiddleware::class,
        ]);

        $router->aliasMiddleware(self::MIDDLEWARE_ALIAS_API_AUTH, ApiAuthMiddleware::class);

        // Register API routes
        $this->registerApiRoutes();
    }

    /**
     * Register any package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/citadel.php', 'citadel');

        // Register the DataStore singleton first since other components depend on it
        $this->registerDataStore();

        // Register the main Citadel service
        $this->app->singleton(Citadel::class, function ($app) {
            return new Citadel($app->make(DataStore::class));
        });

        // Register analyzers and middleware
        $this->registerAnalyzers();
        $this->registerMiddleware();

        // Register API controller
        $this->app->singleton(CitadelApiController::class, function ($app) {
            return new CitadelApiController($app->make(DataStore::class));
        });
    }

    /**
     * Register API routes.
     */
    protected function registerApiRoutes(): void
    {
        // Only register API routes if they're enabled in the config
        if (! config(CitadelConfig::KEY_API_ENABLED, false)) {
            return;
        }

        $prefix = config(CitadelConfig::KEY_API_PREFIX, 'api/citadel');
        $middlewareGroups = ['api'];

        // Add the API auth middleware if a token is configured
        if (! empty(config(CitadelConfig::KEY_API_TOKEN))) {
            $middlewareGroups[] = self::MIDDLEWARE_ALIAS_API_AUTH;
        } else {
            // Log a warning if API is enabled but no token is configured
            $this->app->make('log')->warning('Citadel API is enabled but no API token is configured. This is a security risk.');
        }

        Route::prefix($prefix)
            ->middleware($middlewareGroups)
            ->group(function () {
                // Ban endpoint
                Route::post('/ban', [CitadelApiController::class, 'ban'])
                    ->name('citadel.api.ban');

                // Unban endpoint
                Route::post('/unban', [CitadelApiController::class, 'unban'])
                    ->name('citadel.api.unban');

                // Status endpoint - allows checking if the API is accessible
                Route::get('/status', function () {
                    return response()->json([
                        'status' => 'ok',
                        'version' => config('citadel.version', '1.1.0'),
                        'timestamp' => now()->toIso8601String(),
                    ]);
                })->name('citadel.api.status');
            });
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

        // Register middleware for active analyzers
        $this->app->singleton(ProtectRouteMiddleware::class, function ($app) {
            // Get all analyzers classes, grouped by type
            $analyzers = $this->groupAnalyzersByType();

            // Create and return the middleware with active analyzers and DataStore injected
            return new ProtectRouteMiddleware(
                $analyzers[self::ANALYZER_GROUP_ACTIVE],
                $app->make(DataStore::class)
            );
        });

        // Register the middleware for passive analyzers
        $this->app->singleton(PostProtectRouteMiddleware::class, function ($app) {
            // Get all analyzers classes, grouped by type
            $analyzers = $this->groupAnalyzersByType();

            // Create and return the middleware with passive analyzers and DataStore injected
            return new PostProtectRouteMiddleware(
                $analyzers[self::ANALYZER_GROUP_PASSIVE],
                $app->make(DataStore::class)
            );
        });

        // Register API auth middleware
        $this->app->singleton(ApiAuthMiddleware::class);
    }

    /**
     * Group analyzers by their type (active/passive) and other properties
     *
     * @return array<string, array<IRequestAnalyzer>>
     */
    protected function groupAnalyzersByType(): array
    {
        // Discover all analyzer classes
        $analyzerClasses = $this->discoverAnalyzers();

        $active = [];
        $passive = [];
        $payloadScanners = [];

        // Group analyzers by their properties
        foreach ($analyzerClasses as $class) {
            /** @var IRequestAnalyzer $analyzer */
            $analyzer = $this->app->make($class);

            if (! $analyzer->isEnabled()) {
                continue;
            }

            if ($analyzer->scansPayload()) {
                $payloadScanners[] = $analyzer;
            }

            if ($analyzer->isActive()) {
                $active[] = $analyzer;
            } else {
                $passive[] = $analyzer;
            }
        }

        return [
            self::ANALYZER_GROUP_ACTIVE => $active,
            self::ANALYZER_GROUP_PASSIVE => $passive,
            self::ANALYZER_GROUP_PAYLOAD => $payloadScanners,
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
            ->map(function ($file) use ($namespace): string|null {
                $class = $namespace.$file->getBasename('.php');

                // Skip the interface itself and abstract classes
                if (! class_exists($class) ||
                    (new \ReflectionClass($class))->isInterface() ||
                    (new \ReflectionClass($class))->isAbstract()) {
                    return null;
                }

                // Check if class implements IRequestAnalyzer
                if (in_array(IRequestAnalyzer::class, class_implements($class) ?: [])) {
                    return $class;
                }

                return null;
            })
            ->filter()
            ->values();
    }
}
