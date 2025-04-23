<?php

namespace TheRealMkadmi\Citadel\IpTree;

use Illuminate\Support\Facades\Redis;

class RedisSortedSetIpTree implements IpTree
{
    protected string $indexKey;
    protected string $dataKey;

    /**
     * @param string $indexKey Redis sorted set key for end-of-range scores
     * @param string $dataKey  Redis hash key for CIDR metadata
     */
    public function __construct(string $indexKey, string $dataKey)
    {
        $this->indexKey = $indexKey;
        $this->dataKey  = $dataKey;
    }

    /**
     * Insert a CIDR block or single IP (/32) into the tree.
     *
     * @param string $cidrOrIp CIDR (e.g. "1.2.3.0/24") or IP ("1.2.3.4")
     */
    public function insertIp(string $cidrOrIp): void
    {
        if (strpos($cidrOrIp, '/') === false) {
            $cidrOrIp .= '/32';
        }
        [$net, $bits] = explode('/', $cidrOrIp, 2);
        $mask = (int) $bits;
        $start = $this->ipToInt($net);
        $end   = $start + ((1 << (32 - $mask)) - 1);

        Redis::pipeline(function ($pipe) use ($cidrOrIp, $start, $end) {
            $pipe->zadd($this->indexKey, [$cidrOrIp => $end]);
            $pipe->hset(
                $this->dataKey,
                $cidrOrIp,
                json_encode(['start' => $start, 'end' => $end, 'expires_at' => null])
            );
        });
    }

    /**
     * Check whether an IP is contained in the tree.
     *
     * @param string $ip IPv4 address
     * @return bool
     */
    public function containsIp(string $ip): bool
    {
        $score = $this->ipToInt($ip);
        $now   = time();

        // Single pipeline: find top CIDR, fetch its metadata
        [$candidates, $raw] = Redis::pipeline(function ($pipe) use ($score) {
            $pipe->zrevrangebyscore(
                $this->indexKey,
                $score,
                '-inf',
                ['limit' => [0, 1]]
            );
            $pipe->hget($this->dataKey, Redis::rawCommand('ZRANGE')[0] ?? '');
        });

        if (empty($candidates) || ! is_string($raw) || $raw === '') {
            return false;
        }

        $info = json_decode($raw, true);

        // expiration check
        if (isset($info['expires_at']) && $info['expires_at'] !== null && $now >= $info['expires_at']) {
            return false;
        }

        // range check
        return $score >= ($info['start'] ?? 0) && $score <= ($info['end'] ?? PHP_INT_MAX);
    }

    /**
     * Convert dotted-quad IPv4 to unsigned int.
     */
    private function ipToInt(string $ip): int
    {
        return (int) sprintf('%u', ip2long($ip));
    }
}