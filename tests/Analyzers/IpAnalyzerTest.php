<?php

namespace TheRealMkadmi\Citadel\Tests\Feature;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use TheRealMkadmi\Citadel\Analyzers\IpAnalyzer;
use TheRealMkadmi\Citadel\Clients\IncolumitasApiClient;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\ArrayDataStore;
use TheRealMkadmi\Citadel\Tests\TestCase;

class IpAnalyzerTest extends TestCase
{
    /**
     * The data store instance used for testing.
     */
    protected ArrayDataStore $dataStore;

    /**
     * The IpAnalyzer instance.
     */
    protected IpAnalyzer $analyzer;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Create a real data store instance
        $this->dataStore = new ArrayDataStore;

        // Configure test weights using constants from CitadelConfig
        Config::set(CitadelConfig::KEY_IP.'.weights', [
            'bogon' => 80.0,
            'datacenter' => 30.0,
            'tor' => 60.0,
            'proxy' => 50.0,
            'vpn' => 40.0,
            'abuser' => 70.0,
            'satellite' => 10.0,
            'mobile' => -10.0,
            'crawler' => 20.0,
        ]);
        Config::set(CitadelConfig::KEY_IP.'.enable_ip_analyzer', true);

        // Create a real API client with shorter timeout for testing
        $apiClient = new IncolumitasApiClient([
            'timeout' => 5,
            'retry' => true,
            'max_retries' => 1,
            'retry_delay' => 200,
        ]);

        // Create the analyzer with real dependencies
        $this->analyzer = new IpAnalyzer($this->dataStore, $apiClient);
    }

    #[Test]
    public function it_returns_zero_for_private_ip()
    {
        // Create a request with a private IP
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint',
            'GET',
            'https://example.com/test',
            [],
            ['REMOTE_ADDR' => '10.0.0.1']
        );

        // Analyze with actual analyzer (no mocking)
        $score = $this->analyzer->analyze($request);

        $this->assertEquals(0, $score, 'Expected IpAnalyzer to return zero for private IPs.');
    }

    #[Test]
    public function it_caches_ip_analysis_results()
    {
        // Create requests to Google's public DNS
        $request1 = $this->makeFingerprintedRequest(
            'test-fingerprint-1',
            'GET',
            'https://example.com/test',
            [],
            ['REMOTE_ADDR' => '8.8.8.8']
        );
        $request2 = $this->makeFingerprintedRequest(
            'test-fingerprint-2',
            'GET',
            'https://example.com/test',
            [],
            ['REMOTE_ADDR' => '8.8.8.8']
        );

        // First request should query the API
        $score1 = $this->analyzer->analyze($request1);

        // Second request should use cached results
        $score2 = $this->analyzer->analyze($request2);

        $this->assertEquals($score1, $score2, 'Expected IpAnalyzer to cache analysis results.');

        // Google's public DNS should be exactly identified as a datacenter IP
        $datacenterWeight = config(CitadelConfig::KEY_IP.'.weights.datacenter');
        $this->assertEquals($datacenterWeight, $score1, 'Expected Google DNS to have exactly the datacenter weight score');
    }

    #[Test]
    public function it_handles_localhost_ip_correctly()
    {
        // Create a request with localhost IP
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint',
            'GET',
            'https://example.com/test',
            [],
            ['REMOTE_ADDR' => '127.0.0.1']
        );

        // Analyze with actual analyzer (no mocking)
        $score = $this->analyzer->analyze($request);

        // Localhost is a private IP, should return 0
        $this->assertEquals(0, $score, 'Expected localhost to return zero score');
    }

    #[Test]
    public function it_handles_ipv6_localhost_correctly()
    {
        // Create a request with IPv6 localhost
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint',
            'GET',
            'https://example.com/test',
            [],
            ['REMOTE_ADDR' => '::1']
        );

        // Analyze with actual analyzer (no mocking)
        $score = $this->analyzer->analyze($request);

        // IPv6 localhost is a private IP, should return 0
        $this->assertEquals(0, $score, 'Expected IPv6 localhost to return zero score');
    }

    #[Test]
    public function it_correctly_identifies_google_dns_as_datacenter()
    {
        // Create a request with Google's DNS (a well-known datacenter IP)
        $request = $this->makeFingerprintedRequest(
            'test-fingerprint',
            'GET',
            'https://example.com/test',
            [],
            ['REMOTE_ADDR' => '8.8.8.8']
        );

        // Analyze with actual analyzer (no mocking)
        $score = $this->analyzer->analyze($request);

        // Verify that the score matches what we expect for a datacenter
        // The datacenter weight in setUp() is 30.0
        $datacenterWeight = config(CitadelConfig::KEY_IP.'.weights.datacenter');
        $this->assertEquals($datacenterWeight, $score, 'Expected Google DNS to be correctly identified as a datacenter IP');
    }
}
