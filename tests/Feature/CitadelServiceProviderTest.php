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
        $router = $this->app->make('router');
        $routes = $router->getRoutes();
        $banRoute = $routes->getByName(CitadelServiceProvider::ROUTE_NAME_BAN);
        $this->assertNotNull($banRoute, 'The ban route is not registered.');
        
        $unbanRoute = $routes->getByName(CitadelServiceProvider::ROUTE_NAME_UNBAN);
        $this->assertNotNull($unbanRoute, 'The unban route is not registered.');

        $statusRoute = $routes->getByName(CitadelServiceProvider::ROUTE_NAME_STATUS);
        $this->assertNotNull($statusRoute, 'The status route is not registered.');
    }
}
