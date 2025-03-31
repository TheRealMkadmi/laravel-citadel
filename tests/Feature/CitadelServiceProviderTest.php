<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
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
        Config::set('citadel.api.enabled', true);
        Config::set('citadel.api.prefix', 'api/citadel');

        $this->app->register(CitadelServiceProvider::class);

        $routes = Route::getRoutes();

        $this->assertTrue($routes->hasNamedRoute('citadel.api.ban'), 'Expected ban API route to be registered.');
        $this->assertTrue($routes->hasNamedRoute('citadel.api.unban'), 'Expected unban API route to be registered.');
        $this->assertTrue($routes->hasNamedRoute('citadel.api.status'), 'Expected status API route to be registered.');
    }
}