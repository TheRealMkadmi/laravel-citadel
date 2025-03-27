<?php

namespace TheRealMkadmi\Citadel;

use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Str;
use Laravel\Octane\Server;
use Spatie\LaravelPackageTools\Commands\InstallCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Symfony\Component\Finder\Finder;
use TheRealMkadmi\Citadel\Analyzers\IRequestAnalyzer;
use TheRealMkadmi\Citadel\Commands\CitadelCommand;
use TheRealMkadmi\Citadel\Components\Fingerprint;
use TheRealMkadmi\Citadel\Contracts\DataStore;
use TheRealMkadmi\Citadel\DataStores\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStores\OctaneDataStore;
use TheRealMkadmi\Citadel\DataStores\RedisDataStore;
use TheRealMkadmi\Citadel\Middleware\ProtectRouteMiddleware;

class CitadelServiceProvider extends PackageServiceProvider
{
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
            ->hasCommand(CitadelCommand::class)
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
        Request::macro('getFingerprint', fn() => app(Citadel::class)->getFingerprint($this));
        
        // Register middleware
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('citadel', ProtectRouteMiddleware::class);
    }
    
    /**
     * Register any package services.
     *
     * @return void
     */
    public function packageRegistered()
    {
        // Register the DataStore contract and implementation
        $this->registerDataStore();
        
        // Register the main Citadel class
        $this->app->singleton(Citadel::class, fn($app) => new Citadel());
        
        // Register all analyzers and the middleware
        $this->registerAnalyzers();
        $this->registerMiddleware();
    }
    
    /**
     * Register the DataStore contract and implementation.
     *
     * @return void
     */
    protected function registerDataStore()
    {
        $this->app->singleton(DataStore::class, function ($app) {
            $driver = config('citadel.cache.driver', 'auto');
            
            // If a specific driver is configured, use it directly
            if ($driver !== 'auto') {
                return $this->resolveDataStoreByDriver($driver);
            }
            
            // Auto-detect the best available driver based on configuration preferences
            return $this->resolveAutoDataStore($app);
        });
    }
    
    /**
     * Resolve the appropriate DataStore for auto mode based on environment and preferences.
     * 
     * @param \Illuminate\Contracts\Foundation\Application $app
     * @return \TheRealMkadmi\Citadel\Contracts\DataStore
     */
    protected function resolveAutoDataStore($app): DataStore
    {
        // Get preference configuration
        $preferOctane = config('citadel.cache.prefer_octane', true);
        $preferRedis = config('citadel.cache.prefer_redis', true);
        
        // If Octane is available and preferred, use Octane store
        if ($preferOctane && $app->bound(Server::class)) {
            return new OctaneDataStore();
        }
        
        // If Redis is available and preferred, use Redis store
        if ($preferRedis && $this->isRedisAvailable()) {
            return new RedisDataStore();
        }
        
        // Fall back to the default cache store defined in cache.php
        $defaultDriver = config('cache.default', 'array');
        return $this->resolveDataStoreByDriver($defaultDriver);
    }
    
    /**
     * Resolve a DataStore implementation by driver name.
     *
     * @param string $driver
     * @return \TheRealMkadmi\Citadel\Contracts\DataStore
     */
    protected function resolveDataStoreByDriver(string $driver): DataStore
    {
        return match ($driver) {
            'redis' => new RedisDataStore(),
            'octane' => new OctaneDataStore(),
            default => new ArrayDataStore(),
        };
    }
    
    /**
     * Check if Redis is available and configured.
     *
     * @return bool
     */
    protected function isRedisAvailable(): bool
    {
        return class_exists('Redis') && 
               config('database.redis.client', null) !== null &&
               !empty(config('database.redis.default', []));
    }
    
    /**
     * Register the request analyzers.
     *
     * @return void
     */
    protected function registerAnalyzers()
    {
        // Discover all classes that implement IRequestAnalyzer
        $analyzers = $this->discoverAnalyzers();
        
        // Bind each analyzer class to the container
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
        $this->app->singleton(ProtectRouteMiddleware::class, function ($app) {
            // Resolve all analyzer instances from the container
            $analyzers = $this->discoverAnalyzers()->map(fn($class) => $app->make($class))->toArray();
            
            // Create and return the middleware with all analyzers injected
            return new ProtectRouteMiddleware($analyzers);
        });
    }
    
    /**
     * Discover all request analyzer implementations.
     *
     * @return Collection
     */
    protected function discoverAnalyzers(): Collection
    {
        $analyzersPath = __DIR__ . '/Analyzers';
        $namespace = 'TheRealMkadmi\\Citadel\\Analyzers\\';
        
        $finder = new Finder();
        $finder->files()->in($analyzersPath)->name('*.php');
        
        return collect($finder)
            ->map(function ($file) use ($namespace): string|null {
                $class = $namespace . $file->getBasename('.php');
                
                // Skip the interface itself and abstract classes
                if (!class_exists($class) || 
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
