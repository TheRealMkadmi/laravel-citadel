<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
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
        // Ensure we're starting with a clean route collection
        Route::getRoutes()->refreshNameLookups();
        
        // Configure API settings directly in the config repository
        config([CitadelConfig::KEY_API_ENABLED => true]);
        config([CitadelConfig::KEY_API_PREFIX => 'api/citadel']);
        
        // Create a fresh instance and boot it properly
        $provider = new CitadelServiceProvider($this->app);
        $provider->register();
        $provider->boot();
        
        // Force packageBooted to be called to ensure routes are registered
        $provider->packageBooted();
        
        // Access the route collection
        $routes = Route::getRoutes();
        
        // Debug output to help troubleshoot
        $routeNames = collect($routes->getRoutesByName())->keys()->toArray();
        
        // Assert that our routes exist
        $this->assertTrue(
            $routes->hasNamedRoute('citadel.api.ban'), 
            'Expected ban API route to be registered. Available routes: ' . implode(', ', $routeNames)
        );
        $this->assertTrue($routes->hasNamedRoute('citadel.api.unban'), 'Expected unban API route to be registered.');
        $this->assertTrue($routes->hasNamedRoute('citadel.api.status'), 'Expected status API route to be registered.');
    }
}
