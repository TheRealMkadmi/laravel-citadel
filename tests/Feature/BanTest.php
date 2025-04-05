<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Citadel;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Enums\BanType;
use TheRealMkadmi\Citadel\Middleware\BanMiddleware;
use TheRealMkadmi\Citadel\Tests\TestCase;

class BanTest extends TestCase
{
    protected Citadel $citadel;

    protected ArrayDataStore $dataStore;

    protected BanMiddleware $middleware;

    protected const TEST_IP = '192.168.1.1';

    protected const TEST_FINGERPRINT = 'test-fingerprint-12345';

    protected const TEST_REASON = 'Suspicious activity';

    protected function setUp(): void
    {
        parent::setUp();

        // Set up DataStore with a fresh instance for each test
        $this->dataStore = new ArrayDataStore;
        $this->app->instance(ArrayDataStore::class, $this->dataStore);

        // Create Citadel instance with the DataStore
        $this->citadel = new Citadel($this->dataStore);

        // Create BanMiddleware with the DataStore
        $this->middleware = new BanMiddleware($this->dataStore);

        // Ensure middleware is enabled for tests
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ENABLED, true);
        Config::set(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true);
    }

    #[Test]
    public function it_can_ban_ip_address()
    {
        // Ban an IP address
        $result = $this->citadel->banIp(self::TEST_IP, null, self::TEST_REASON);

        // Verify ban was set successfully
        $this->assertTrue($result);

        // Verify IP is banned
        $this->assertTrue($this->citadel->isBanned(self::TEST_IP, BanType::IP));

        // Verify ban details
        $banDetails = $this->citadel->getBan(self::TEST_IP, BanType::IP);
        $this->assertNotNull($banDetails);
        $this->assertEquals(self::TEST_REASON, $banDetails['reason']);
        $this->assertEquals(BanType::IP->value, $banDetails['type']);
        $this->assertArrayHasKey('timestamp', $banDetails);
    }

    #[Test]
    public function it_can_ban_fingerprint()
    {
        // Ban a fingerprint
        $result = $this->citadel->banFingerprint(self::TEST_FINGERPRINT, 3600, self::TEST_REASON);

        // Verify ban was set successfully
        $this->assertTrue($result);

        // Verify fingerprint is banned
        $this->assertTrue($this->citadel->isBanned(self::TEST_FINGERPRINT, BanType::FINGERPRINT));

        // Verify ban details
        $banDetails = $this->citadel->getBan(self::TEST_FINGERPRINT, BanType::FINGERPRINT);
        $this->assertNotNull($banDetails);
        $this->assertEquals(self::TEST_REASON, $banDetails['reason']);
        $this->assertEquals(BanType::FINGERPRINT->value, $banDetails['type']);
        $this->assertArrayHasKey('timestamp', $banDetails);
    }

    #[Test]
    public function it_can_unban_ip_address()
    {
        // First ban an IP
        $this->citadel->banIp(self::TEST_IP);

        // Verify IP is banned
        $this->assertTrue($this->citadel->isBanned(self::TEST_IP, BanType::IP));

        // Now unban it
        $result = $this->citadel->unban(self::TEST_IP, BanType::IP);

        // Verify unban was successful
        $this->assertTrue($result);

        // Verify IP is no longer banned
        $this->assertFalse($this->citadel->isBanned(self::TEST_IP, BanType::IP));

        // Verify ban details no longer exist
        $this->assertNull($this->citadel->getBan(self::TEST_IP, BanType::IP));
    }

    #[Test]
    public function it_can_unban_fingerprint()
    {
        // First ban a fingerprint
        $this->citadel->banFingerprint(self::TEST_FINGERPRINT);

        // Verify fingerprint is banned
        $this->assertTrue($this->citadel->isBanned(self::TEST_FINGERPRINT, BanType::FINGERPRINT));

        // Now unban it
        $result = $this->citadel->unban(self::TEST_FINGERPRINT, BanType::FINGERPRINT);

        // Verify unban was successful
        $this->assertTrue($result);

        // Verify fingerprint is no longer banned
        $this->assertFalse($this->citadel->isBanned(self::TEST_FINGERPRINT, BanType::FINGERPRINT));
    }

    #[Test]
    public function ban_middleware_blocks_banned_ip()
    {
        // Ban an IP
        $this->citadel->banIp(self::TEST_IP);

        // Create a request with the banned IP
        $request = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => self::TEST_IP,
        ]);

        // Apply the middleware
        $response = $this->middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify request is blocked (not allowed through)
        $this->assertNotEquals('allowed', $response);

        // Verify the response is a 403 Forbidden
        $this->assertEquals(403, $response->getStatusCode());
    }

    #[Test]
    public function ban_middleware_blocks_banned_fingerprint()
    {
        // Ban a fingerprint
        $this->citadel->banFingerprint(self::TEST_FINGERPRINT);

        // Create a request with the banned fingerprint
        $request = $this->makeFingerprintedRequest(self::TEST_FINGERPRINT);

        // Apply the middleware
        $response = $this->middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify request is blocked (not allowed through)
        $this->assertNotEquals('allowed', $response);

        // Verify the response is a 403 Forbidden
        $this->assertEquals(403, $response->getStatusCode());
    }

    #[Test]
    public function ban_middleware_allows_non_banned_users()
    {
        // Create a request with non-banned details
        $request = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.2',
        ]);

        // Apply the middleware
        $response = $this->middleware->handle($request, function ($req) {
            return 'allowed';
        });

        // Verify request is allowed through
        $this->assertEquals('allowed', $response);
    }

    #[Test]
    public function temporary_bans_expire_after_duration()
    {
        // Create a temporary ban (1 second)
        $this->citadel->banIp(self::TEST_IP, 1, 'Temporary ban');

        // Verify the IP is banned initially
        $this->assertTrue($this->citadel->isBanned(self::TEST_IP, BanType::IP));

        // Wait for the ban to expire
        sleep(2);

        // Verify the ban has expired
        $this->assertFalse($this->citadel->isBanned(self::TEST_IP, BanType::IP));
    }

    #[Test]
    public function permanent_bans_do_not_expire()
    {
        // Default duration (null) is permanent
        $this->citadel->banIp(self::TEST_IP, null, 'Permanent ban');

        // Set the ban TTL to a very short time (to test permanence)
        Config::set(CitadelConfig::KEY_BAN_DURATION, 1);

        // Verify the IP is banned initially
        $this->assertTrue($this->citadel->isBanned(self::TEST_IP, BanType::IP));

        // Wait longer than the configured TTL
        sleep(2);

        // Verify the ban is still active (permanent)
        $this->assertTrue($this->citadel->isBanned(self::TEST_IP, BanType::IP));
    }

    #[Test]
    public function ban_keys_are_properly_formatted()
    {
        // Use a tricky string with special characters that should be slugified
        $trickyIp = '192.168.1.1!@#$%^&*()_+';
        $this->citadel->banIp($trickyIp);

        // Retrieve the ban through the API to verify it was stored correctly
        $this->assertTrue($this->citadel->isBanned($trickyIp, BanType::IP));

        // Test with Unicode characters
        $unicodeFingerprint = 'öüäß❤️✓☺♤♧';
        $this->citadel->banFingerprint($unicodeFingerprint);

        // Verify the Unicode fingerprint ban works
        $this->assertTrue($this->citadel->isBanned($unicodeFingerprint, BanType::FINGERPRINT));
    }

    #[Test]
    public function it_handles_ban_with_special_characters()
    {
        $specialCharsIdentifier = "special~!@#$%^&*()_+{}|:\"<>?[]\;',./chars";

        // Ban the identifier with special chars
        $this->citadel->banFingerprint($specialCharsIdentifier);

        // Should successfully identify the ban despite the special chars
        $this->assertTrue(
            $this->citadel->isBanned($specialCharsIdentifier, BanType::FINGERPRINT),
            'Failed to identify ban with special characters'
        );
    }
}
