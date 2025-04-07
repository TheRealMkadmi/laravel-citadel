<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class DataStorePersistenceTest extends TestCase
{
    private const TEST_ENDPOINT = '/datastore-persistence-test';

    private const TEST_FINGERPRINT = 'data-persistence-fingerprint';

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure we're using a consistent cache driver
        Config::set(CitadelConfig::KEY_CACHE_DRIVER, ArrayDataStore::STORE_IDENTIFIER);
        Config::set(CitadelConfig::KEY_CACHE_PREFIX, 'citadel-persistence-test:');

        // Set up test routes
        $this->defineTestRoutes($this->app);
    }

    protected function defineTestRoutes($app): void
    {
        $app['router']->get(self::TEST_ENDPOINT, function (Request $request) {
            // Get the DataStore from the container
            $dataStore = app(DataStore::class);

            // Get or increment visit count for this fingerprint
            $countKey = 'visit_count:'.$request->getFingerprint();
            $count = $dataStore->getValue($countKey) ?? 0;
            $dataStore->setValue($countKey, $count + 1);

            return response()->json([
                'success' => true,
                'fingerprint' => $request->getFingerprint(),
                'visit_count' => $count + 1,
            ]);
        })->middleware('citadel-protect');
    }

    /**
     * Clears any cached data to ensure a clean slate for each test
     */
    protected function clearCachedData(): void
    {
        $dataStore = $this->app->make(DataStore::class);
        $prefix = Config::get(CitadelConfig::KEY_CACHE_PREFIX, 'citadel:');

        // Use the DataStore's internal cache to clear everything with our prefix
        Cache::store(ArrayDataStore::STORE_IDENTIFIER)->flush();
    }

    #[Test]
    public function datastore_correctly_persists_data_between_requests()
    {
        // Clear any cached data
        $this->clearCachedData();

        // Request 1 - Should be first visit
        $response1 = $this->getJson(
            self::TEST_ENDPOINT,
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );

        $response1->assertStatus(200);
        $response1->assertJson(['visit_count' => 1]);

        // Request 2 - Should increment visit count
        $response2 = $this->getJson(
            self::TEST_ENDPOINT,
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );

        $response2->assertStatus(200);
        $response2->assertJson(['visit_count' => 2]);

        // Request 3 - Should increment again
        $response3 = $this->getJson(
            self::TEST_ENDPOINT,
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );

        $response3->assertStatus(200);
        $response3->assertJson(['visit_count' => 3]);
    }

    #[Test]
    public function datastore_isolates_data_between_different_fingerprints()
    {
        // Clear any cached data
        $this->clearCachedData();

        $fingerprint1 = 'test-fingerprint-1';
        $fingerprint2 = 'test-fingerprint-2';

        // First fingerprint visits
        $response1a = $this->getJson(self::TEST_ENDPOINT, ['X-Fingerprint' => $fingerprint1]);
        $response1a->assertJson(['visit_count' => 1]);

        $response1b = $this->getJson(self::TEST_ENDPOINT, ['X-Fingerprint' => $fingerprint1]);
        $response1b->assertJson(['visit_count' => 2]);

        // Second fingerprint should start fresh
        $response2 = $this->getJson(self::TEST_ENDPOINT, ['X-Fingerprint' => $fingerprint2]);
        $response2->assertJson(['visit_count' => 1]);

        // Go back to first fingerprint - should remember its count
        $response1c = $this->getJson(self::TEST_ENDPOINT, ['X-Fingerprint' => $fingerprint1]);
        $response1c->assertJson(['visit_count' => 3]);
    }

    #[Test]
    public function data_correctly_expires_after_ttl()
    {
        // Clear any cached data
        $this->clearCachedData();

        // Configure a very short TTL for testing
        Config::set(CitadelConfig::KEY_CACHE_DEFAULT_TTL, 1); // 1 second

        // First request
        $response1 = $this->getJson(
            self::TEST_ENDPOINT,
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );
        $response1->assertJson(['visit_count' => 1]);

        // Wait for TTL to expire
        sleep(2);

        // Second request - should see it as first visit again
        $response2 = $this->getJson(
            self::TEST_ENDPOINT,
            ['X-Fingerprint' => self::TEST_FINGERPRINT]
        );
        $response2->assertJson(['visit_count' => 1]);
    }
}
