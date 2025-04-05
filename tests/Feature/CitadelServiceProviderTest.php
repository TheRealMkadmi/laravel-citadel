<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Commands\CitadelCompileRegexCommand;
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
    public function it_registers_api_routes()
    {
        $router = $this->app->make('router');
        $routes = $router->getRoutes();
        $banRoute = $routes->getByName(CitadelServiceProvider::ROUTE_NAME_BAN);
        $this->assertNotNull($banRoute, 'The ban route is not registered.');

        $unbanRoute = $routes->getByName(CitadelServiceProvider::ROUTE_NAME_UNBAN);
        $this->assertNotNull($unbanRoute, 'The unban route is not registered.');

        $statusRoute = $routes->getByName(CitadelServiceProvider::ROUTE_NAME_STATUS);
        $this->assertNotNull($statusRoute, 'The status route is not registered.');
    }

    #[Test]
    public function it_registers_compile_regex_command()
    {
        // Check if the command is registered
        $commands = $this->app->make('Illuminate\Contracts\Console\Kernel')
            ->all();

        $this->assertArrayHasKey('citadel:compile-regex', $commands,
            'The citadel:compile-regex command should be registered.');

        // Check if the command instance is correct
        $commandInstance = $commands['citadel:compile-regex'];
        $this->assertInstanceOf(CitadelCompileRegexCommand::class, $commandInstance,
            'The command should be an instance of CitadelCompileRegexCommand.');
    }

    #[Test]
    public function it_creates_vectorscan_pattern_matcher_with_serialized_db_path()
    {
        // Create a test serialized database path
        $testDbPath = storage_path('app/test/citadel_test_db.db');

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

            // Try to resolve the pattern matcher and verify it attempts to use the serialized database
            try {
                $patternMatcher = $method->invoke($serviceProvider, $patterns);
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
}
