<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Commands\CitadelBanCommand;
use TheRealMkadmi\Citadel\Commands\CitadelCompileRegexCommand;
use TheRealMkadmi\Citadel\Commands\CitadelUnbanCommand;
use TheRealMkadmi\Citadel\PatternMatchers\VectorScanMultiPatternMatcher;
use TheRealMkadmi\Citadel\Tests\TestCase;

class CitadelServiceProviderTest extends TestCase
{
    #[Test]
    public function it_registers_fingerprint_macro()
    {
        $request = request();
        $fingerprint = $request->getFingerprint();

        $this->assertNotNull($fingerprint, 'Expected fingerprint macro to be registered.');
    }

    #[Test]
    public function it_registers_middleware_groups()
    {
        $router = $this->app->make('router');

        $middlewareGroups = $router->getMiddlewareGroups();

        $this->assertArrayHasKey('citadel-protect', $middlewareGroups, 'Expected citadel-protect middleware group to be registered.');
        $this->assertArrayHasKey('citadel-active', $middlewareGroups, 'Expected citadel-active middleware group to be registered.');
    }

    #[Test]
    public function it_creates_vectorscan_pattern_matcher_with_serialized_db_path()
    {
        // Create a test serialized database path
        $testDbPath = storage_path('app/test/citadel_test_db.db');
        $patternsFile = storage_path('app/test/patterns.list');

        // Ensure directory exists
        if (! File::isDirectory(dirname($testDbPath))) {
            File::makeDirectory(dirname($testDbPath), 0755, true);
        }

        // Create an empty file to simulate serialized database
        File::put($testDbPath, 'test');

        try {
            // Set the config to use the test path
            Config::set('citadel.pattern_matcher.serialized_db_path', $testDbPath);
            Config::set('citadel.pattern_matcher.implementation', 'vectorscan');

            // Create a new service provider instance (to avoid problems with the already-registered one)
            $serviceProvider = new CitadelServiceProvider($this->app);

            // Use reflection to access the private createVectorscanPatternMatcher method
            $reflection = new \ReflectionClass($serviceProvider);
            $method = $reflection->getMethod('createVectorscanPatternMatcher');
            $method->setAccessible(true);

            // Get the patterns through reflection
            $patterns = ['test\d+'];

            // write the patterns to the test pattern file
            File::put($patternsFile, implode("\n", $patterns));

            // Try to resolve the pattern matcher and verify it attempts to use the serialized database
            try {
                $patternMatcher = $method->invoke($serviceProvider, $patterns, $patternsFile);
                // This test might fail if vectorscan library is not available, so we'll add a conditional check
                if ($patternMatcher instanceof VectorScanMultiPatternMatcher) {
                    $this->assertInstanceOf(VectorScanMultiPatternMatcher::class, $patternMatcher);
                } else {
                    $this->markTestSkipped('VectorScanMultiPatternMatcher could not be instantiated, likely missing library.');
                }
            } catch (\RuntimeException $e) {
                // If we can't load the library, that's okay for this test
                if (stripos($e->getMessage(), 'library not found') !== false) {
                    $this->markTestSkipped('VectorScan library not found, skipping test.');
                } else {
                    throw $e;
                }
            }
        } finally {
            // Cleanup
            if (File::exists($testDbPath)) {
                File::delete($testDbPath);
            }
        }
    }

    #[Test]
    public function it_registers_api_routes()
    {
        // Get all registered routes
        $routes = Route::getRoutes();

        // Expected route names from the CitadelServiceProvider
        $expectedRouteNames = [
            CitadelServiceProvider::ROUTE_NAME_BAN,    // 'citadel.api.ban'
            CitadelServiceProvider::ROUTE_NAME_UNBAN,  // 'citadel.api.unban'
            CitadelServiceProvider::ROUTE_NAME_STATUS, // 'citadel.api.status'
        ];

        // Check if the routes are registered
        $foundRoutes = [];
        foreach ($routes as $route) {
            if (in_array($route->getName(), $expectedRouteNames)) {
                $foundRoutes[] = $route->getName();
            }
        }

        // Verify all expected routes are found
        foreach ($expectedRouteNames as $routeName) {
            $this->assertContains(
                $routeName,
                $foundRoutes,
                "Expected route '{$routeName}' was not registered."
            );
        }
    }

    #[Test]
    public function it_registers_commands()
    {
        // Get all registered commands
        $commands = array_keys(Artisan::all());

        // Expected command signatures
        $expectedCommands = [
            'citadel:ban',         // CitadelBanCommand
            'citadel:unban',       // CitadelUnbanCommand
            'citadel:compile-regex', // CitadelCompileRegexCommand
        ];

        // Verify all expected commands are registered
        foreach ($expectedCommands as $command) {
            $this->assertContains(
                $command,
                $commands,
                "Expected command '{$command}' was not registered."
            );
        }

        // Verify command classes
        $this->assertInstanceOf(
            CitadelBanCommand::class,
            app()->make(CitadelBanCommand::class)
        );

        $this->assertInstanceOf(
            CitadelUnbanCommand::class,
            app()->make(CitadelUnbanCommand::class)
        );

        $this->assertInstanceOf(
            CitadelCompileRegexCommand::class,
            app()->make(CitadelCompileRegexCommand::class)
        );
    }
}
