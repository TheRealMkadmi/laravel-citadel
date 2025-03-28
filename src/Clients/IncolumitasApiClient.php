<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Clients;

use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Http;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class IncolumitasApiClient
{
    protected DataStore $dataStore;

    /**
     * Cache TTL in seconds.
     *
     * @var int
     */
    protected int $cacheTtl;

    /**
     * Create a new API client instance.
     *
     * @param DataStore $dataStore
     * @param int $cacheTtl
     */
    public function __construct(DataStore $dataStore, int $cacheTtl = 3600)
    {
        $this->dataStore = $dataStore;
        $this->cacheTtl = $cacheTtl;
    }

    /**
     * Query the Incolumitas API for information about an IP.
     *
     * @param string $ip
     * @return QueryResult
     *
     * @throws Exception if the API call fails.
     */
    public function query(string $ip): QueryResult
    {
        $cacheKey = "incolumitas:" . $ip;
        $cached = $this->dataStore->getValue($cacheKey);

        if ($cached !== null && $cached instanceof QueryResult) {
            return $cached;
        }

        $response = Http::get('https://api.incolumitas.com/', ['q' => $ip]);

        if (!$response->successful()) {
            throw new Exception("Failed to fetch information for IP: {$ip}");
        }

        $data = $response->json();
        $queryResult = QueryResult::fromArray($data);

        $this->dataStore->setValue($cacheKey, $queryResult, $this->cacheTtl);

        return $queryResult;
    }
}

/**
 * Strongly typed data transfer object for query results.
 */
class QueryResult
{
    public string $ip;
    public string $country;
    public bool $isBogon;
    public bool $isMobile;
    public bool $isSatellite;
    public bool $isCrawler;
    public bool $isDatacenter;
    public bool $isTor;
    public bool $isProxy;
    public bool $isVpn;
    public bool $isAbuser;

    /**
     * Construct the QueryResult from an array.
     *
     * @param string $ip
     * @param string $country
     * @param bool $isBogon
     * @param bool $isMobile
     * @param bool $isSatellite
     * @param bool $isCrawler
     * @param bool $isDatacenter
     * @param bool $isTor
     * @param bool $isProxy
     * @param bool $isVpn
     * @param bool $isAbuser
     */
    public function __construct(
        string $ip,
        string $country,
        bool $isBogon,
        bool $isMobile,
        bool $isSatellite,
        bool $isCrawler,
        bool $isDatacenter,
        bool $isTor,
        bool $isProxy,
        bool $isVpn,
        bool $isAbuser
    ) {
        $this->ip = $ip;
        $this->country = $country;
        $this->isBogon = $isBogon;
        $this->isMobile = $isMobile;
        $this->isSatellite = $isSatellite;
        $this->isCrawler = $isCrawler;
        $this->isDatacenter = $isDatacenter;
        $this->isTor = $isTor;
        $this->isProxy = $isProxy;
        $this->isVpn = $isVpn;
        $this->isAbuser = $isAbuser;
    }

    /**
     * Create a QueryResult instance from an array.
     *
     * @param array $data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            Arr::get($data, 'ip', ''),
            Arr::get($data, 'location.country', ''),
            (bool) Arr::get($data, 'is_bogon', false),
            (bool) Arr::get($data, 'is_mobile', false),
            (bool) Arr::get($data, 'is_satellite', false),
            (bool) Arr::get($data, 'is_crawler', false),
            (bool) Arr::get($data, 'is_datacenter', false),
            (bool) Arr::get($data, 'is_tor', false),
            (bool) Arr::get($data, 'is_proxy', false),
            (bool) Arr::get($data, 'is_vpn', false),
            (bool) Arr::get($data, 'is_abuser', false)
        );
    }
}
