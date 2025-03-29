<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Citadel;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\Tests\TestCase;

class FingerprintExtractionTest extends TestCase
{
    protected string $testFingerprint = 'test-fingerprint-123456789';
    protected string $defaultHeaderName = 'X-Fingerprint';
    protected string $defaultCookieName = 'persistentFingerprint_visitor_id';
    protected string $customHeaderName = 'X-Custom-Fingerprint';
    protected string $customCookieName = 'custom_fingerprint_cookie';
    
    protected function setUp(): void
    {
        parent::setUp();
        
        // Default configuration for tests
        Config::set(CitadelConfig::KEY_HEADER . '.name', $this->defaultHeaderName);
        Config::set(CitadelConfig::KEY_COOKIE . '.name', $this->defaultCookieName);
        Config::set(CitadelConfig::KEY_FEATURES . '.collect_ip', true);
        Config::set(CitadelConfig::KEY_FEATURES . '.collect_user_agent', true);
    }
    
    #[Test]
    public function it_extracts_fingerprint_from_default_header()
    {
        // Create a request with the fingerprint in the default header
        $request = Request::create('https://example.com/test', 'GET');
        $request->headers->set($this->defaultHeaderName, $this->testFingerprint);
        
        // Verify the fingerprint is correctly extracted using the macro
        $this->assertEquals($this->testFingerprint, $request->getFingerprint());
    }
    
    #[Test]
    public function it_extracts_fingerprint_from_custom_header()
    {
        // Configure a custom header name
        Config::set(CitadelConfig::KEY_HEADER . '.name', $this->customHeaderName);
        
        // Create a request with the fingerprint in the custom header
        $request = Request::create('https://example.com/test', 'GET');
        $request->headers->set($this->customHeaderName, $this->testFingerprint);
        
        // Verify the fingerprint is correctly extracted using the macro
        $this->assertEquals($this->testFingerprint, $request->getFingerprint());
    }
    
    #[Test]
    public function it_prefers_header_over_cookie()
    {
        // Create a request with the fingerprint in both header and cookie
        $request = Request::create('https://example.com/test', 'GET');
        $request->headers->set($this->defaultHeaderName, $this->testFingerprint);
        $request->cookies->set($this->defaultCookieName, 'cookie-fingerprint-should-not-be-used');
        
        // Verify the header fingerprint is preferred
        $this->assertEquals($this->testFingerprint, $request->getFingerprint());
    }
    
    #[Test]
    public function it_extracts_fingerprint_from_default_cookie()
    {
        // Create a request with the fingerprint in the default cookie
        $request = Request::create('https://example.com/test', 'GET');
        $request->cookies->set($this->defaultCookieName, $this->testFingerprint);
        
        // Verify the fingerprint is correctly extracted using the macro
        $this->assertEquals($this->testFingerprint, $request->getFingerprint());
    }
    
    #[Test]
    public function it_extracts_fingerprint_from_custom_cookie()
    {
        // Configure a custom cookie name
        Config::set(CitadelConfig::KEY_COOKIE . '.name', $this->customCookieName);
        
        // Create a request with the fingerprint in the custom cookie
        $request = Request::create('https://example.com/test', 'GET');
        $request->cookies->set($this->customCookieName, $this->testFingerprint);
        
        // Verify the fingerprint is correctly extracted using the macro
        $this->assertEquals($this->testFingerprint, $request->getFingerprint());
    }
    
    #[Test]
    public function it_generates_fingerprint_when_no_header_or_cookie()
    {
        // Create a request without any fingerprint in headers or cookies
        $request = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        // Get the fingerprint using the macro
        $fingerprint = $request->getFingerprint();
        
        // Verify a fingerprint was generated
        $this->assertNotNull($fingerprint);
        $this->assertIsString($fingerprint);
        
        // Verify the same request generates the same fingerprint
        $this->assertEquals($fingerprint, $request->getFingerprint());
        
        // Verify the fingerprint matches the expected format (SHA-256 hash)
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $fingerprint);
    }
    
    #[Test]
    public function it_generates_consistent_fingerprint_for_same_ip_and_agent()
    {
        // Create two requests with the same IP and user agent
        $request1 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        $request2 = Request::create('https://example.com/different', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        // Verify both requests generate the same fingerprint
        $this->assertEquals($request1->getFingerprint(), $request2->getFingerprint());
    }
    
    #[Test]
    public function it_generates_different_fingerprint_for_different_ip()
    {
        // Create two requests with different IPs but same user agent
        $request1 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        $request2 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.2',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        // Verify different fingerprints are generated
        $this->assertNotEquals($request1->getFingerprint(), $request2->getFingerprint());
    }
    
    #[Test]
    public function it_respects_disabled_ip_collection()
    {
        // Disable IP collection
        Config::set(CitadelConfig::KEY_FEATURES . '.collect_ip', false);
        
        // Create two requests with different IPs but same user agent
        $request1 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        $request2 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.2',
            'HTTP_USER_AGENT' => 'Test User Agent',
        ]);
        
        // Verify the same fingerprint is generated (IP is ignored)
        $this->assertEquals($request1->getFingerprint(), $request2->getFingerprint());
    }
    
    #[Test]
    public function it_respects_disabled_user_agent_collection()
    {
        // Disable User-Agent collection
        Config::set(CitadelConfig::KEY_FEATURES . '.collect_user_agent', false);
        
        // Create two requests with same IP but different user agents
        $request1 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent 1',
        ]);
        
        $request2 = Request::create('https://example.com/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
            'HTTP_USER_AGENT' => 'Test User Agent 2',
        ]);
        
        // Verify the same fingerprint is generated (User-Agent is ignored)
        $this->assertEquals($request1->getFingerprint(), $request2->getFingerprint());
    }
    
    #[Test]
    public function it_returns_null_when_no_data_available_for_fingerprinting()
    {
        // Disable both IP and User-Agent collection
        Config::set(CitadelConfig::KEY_FEATURES . '.collect_ip', false);
        Config::set(CitadelConfig::KEY_FEATURES . '.collect_user_agent', false);
        
        // Create a request without any headers or cookies
        $request = Request::create('https://example.com/test', 'GET');
        
        // Verify null is returned when no data is available for fingerprinting
        $this->assertNull($request->getFingerprint());
    }
}