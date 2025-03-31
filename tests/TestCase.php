<?php

namespace TheRealMkadmi\Citadel\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as Orchestra;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;

class TestCase extends Orchestra
{
    use WithWorkbench;

    protected $enablesPackageDiscoveries = true;

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure we're using Array cache driver for all tests
        Config::set(CitadelConfig::KEY_CACHE_DRIVER, ArrayDataStore::STORE_IDENTIFIER);
        Config::set(CitadelConfig::KEY_CACHE.'.prefer_redis', false);
        Config::set('cache.default', 'array');

        Config::set('logging.default', 'stack');
        Config::set('logging.channels.stack', [
            'driver' => 'stack',
            'channels' => ['single', 'stderr'], // Or ['daily', 'stderr'] for rotation
            'ignore_exceptions' => false,
        ]);
        Config::set('logging.channels.single.path', storage_path('logs/laravel.log'));
        Config::set('logging.channels.stderr', [
            'driver' => 'monolog',
            'handler' => \Monolog\Handler\StreamHandler::class,
            'with' => [
                'stream' => 'php://stderr',
            ],
        ]);
    }

    protected function getPackageProviders($app)
    {
        return [
            CitadelServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app)
    {
        // Set up environment to avoid Redis
        $app['config']->set('database.redis.client', null);

        // Configure caching to use array driver
        $app['config']->set('cache.default', 'array');
        $app['config']->set('cache.stores.array', [
            'driver' => 'array',
            'serialize' => false,
        ]);
    }

    /**
     * Create a request with a specific fingerprint.
     * This properly constructs a request with the fingerprint set via header, cookie or request attributes
     * as expected by the Citadel::getFingerprint method.
     *
     * @param  string|null  $fingerprint  The fingerprint to set
     * @param  string  $method  The HTTP method
     * @param  string  $url  The URL
     * @param  array  $parameters  Request parameters
     * @param  bool  $useHeader  Whether to set the fingerprint via header
     * @param  bool  $useCookie  Whether to set the fingerprint via cookie
     */
    protected function makeFingerprintedRequest(
        ?string $fingerprint = null,
        string $method = 'GET',
        string $url = 'https://example.com/test',
        array $parameters = [],
        bool $useHeader = true,
        bool $useCookie = false
    ): Request {
        $request = Request::create($url, $method, $parameters);

        if (! $fingerprint) {
            return $request;
        }

        // Set the fingerprint header if requested
        if ($useHeader) {
            $headerName = Config::get(CitadelConfig::KEY_HEADER.'.name', 'X-Fingerprint');
            $request->headers->set($headerName, $fingerprint);
        }

        // Set the fingerprint cookie if requested
        if ($useCookie) {
            $cookieName = Config::get(CitadelConfig::KEY_COOKIE.'.name', 'persistentFingerprint_visitor_id');
            $request->cookies->set($cookieName, $fingerprint);
        }

        // If neither header nor cookie was set, simulate the behaviors that would
        // cause Citadel::generateFingerprint to produce this specific fingerprint
        if (! $useHeader && ! $useCookie) {
            // Construct the request with specific IP and User-Agent
            // that would generate the requested fingerprint
            $request->server->set('REMOTE_ADDR', $fingerprint);
            $request->headers->set('User-Agent', 'Test-Agent-'.$fingerprint);
        }

        return $request;
    }
}
