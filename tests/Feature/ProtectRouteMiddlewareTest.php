<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Middleware\ProtectRouteMiddleware;
use TheRealMkadmi\Citadel\Tests\TestCase;

class ProtectRouteMiddlewareTest extends TestCase
{
    protected ProtectRouteMiddleware $middleware;

    protected function setUp(): void
    {
        parent::setUp();

        $dataStore = new ArrayDataStore;
        $analyzers = [
            'all' => [],
            'body_analyzers' => [],
            'external_resource_analyzers' => [],
        ];

        $this->middleware = new ProtectRouteMiddleware($analyzers, $dataStore);
    }

    #[Test]
    public function it_skips_request_if_middleware_is_disabled()
    {
        Config::set('citadel.middleware.enabled', false);

        $request = new Request;
        $response = $this->middleware->handle($request, fn ($req) => 'next');

        $this->assertEquals('next', $response, 'Expected middleware to skip processing when disabled.');
    }

    #[Test]
    public function it_blocks_request_with_banned_fingerprint()
    {
        // Set up the mock fingerprint
        $fingerprintValue = 'test-fingerprint';

        // Setup the datastore with banned fingerprint
        $dataStore = new ArrayDataStore;
        $dataStore->setValue('ban:'.$fingerprintValue, true);

        // Setup the middleware with our datastore
        $middleware = new ProtectRouteMiddleware([], $dataStore);

        // Create a request and mock the fingerprint macro
        $request = $this->createMock(Request::class);
        $request->method('getFingerprint')->willReturn($fingerprintValue);

        // Handle the request
        $response = $middleware->handle($request, fn ($req) => 'next');

        // Assert the response
        $this->assertEquals(403, $response->getStatusCode(), 'Expected middleware to block request with banned fingerprint.');
    }
}
