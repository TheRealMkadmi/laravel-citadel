<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
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
        $dataStore = new ArrayDataStore;
        $dataStore->setValue('ban:test-fingerprint', true);

        $middleware = new ProtectRouteMiddleware([], $dataStore);

        $request = new Request;
        $request->merge(['fingerprint' => 'test-fingerprint']);

        $response = $middleware->handle($request, fn ($req) => 'next');

        $this->assertEquals(403, $response->getStatusCode(), 'Expected middleware to block request with banned fingerprint.');
    }

    #[Test]
    public function it_logs_suspicious_activity()
    {
        Config::set('citadel.middleware.warning_threshold', 80);

        $request = new Request;
        $request->merge(['fingerprint' => 'test-fingerprint']);

        Log::shouldReceive('info')->once()->withArgs(function ($message, $context) {
            return $message === 'Citadel: Suspicious activity detected' && $context['fingerprint'] === 'test-fingerprint';
        });

        $this->middleware->logSuspiciousActivity($request, [
            'total_score' => 85,
            'max_score' => 90,
            'scores' => ['analyzer1' => 85],
        ]);
    }
}
