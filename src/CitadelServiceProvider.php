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
use TheRealMkadmi\Citadel\Commands\CitadelBanCommand;
use TheRealMkadmi\Citadel\Commands\CitadelCommand;
use TheRealMkadmi\Citadel\Commands\CitadelUnbanCommand;
use TheRealMkadmi\Citadel\Components\Fingerprint;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\OctaneDataStore;
use TheRealMkadmi\Citadel\DataStore\RedisDataStore;
use TheRealMkadmi\Citadel\Middleware\BanMiddleware;
use TheRealMkadmi\Citadel\Middleware\GeofenceMiddleware;
use TheRealMkadmi\Citadel\Middleware\PostProtectRouteMiddleware;
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
        Request::macro('getFingerprint', fn() => app(Citadel::class)->getFingerprint($this));
        
        // Register middleware
        $router = $this->app->make(Router::class);
        $router->middlewareGroup('citadel-protect', [
            ProtectRouteMiddleware::class,
            PostProtectRouteMiddleware::class,
            GeofenceMiddleware::class,
            BanMiddleware::class,
        ]);
    }
    
    /**
     * Register any package services.
     *
     * @return void
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
    }

    protected function registerDataStore()
    {
        $this->app->singleton(DataStore::class, function ($app) {
            $driver = config('citadel.cache.driver', 'auto');
            
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
        
        // Fall back to array store
        return new ArrayDataStore();
    }

    protected function resolveDataStoreByDriver(string $driver): DataStore
    {
        return match ($driver) {
            'redis' => new RedisDataStore(),
            'octane' => new OctaneDataStore(),
            default => new ArrayDataStore(),
        };
    }

    protected function isRedisAvailable(): bool
    {
        return class_exists('Redis') && 
               config('database.redis.client', null) !== null &&
               !empty(config('database.redis.default', []));
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
        
        $this->app->singleton(ProtectRouteMiddleware::class, function ($app) {
            // Get the analyzer class names
            $analyzerClasses = $this->discoverAnalyzers();
            
            // Resolve all analyzer instances from the container
            $analyzers = $analyzerClasses->map(fn($class) => $app->make($class))->toArray();
            
            // Create and return the middleware with all analyzers and DataStore injected
            return new ProtectRouteMiddleware(
                $analyzers,
                $app->make(DataStore::class)
            );
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
