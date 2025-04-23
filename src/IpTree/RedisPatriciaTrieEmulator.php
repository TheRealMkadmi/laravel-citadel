<?php

namespace TheRealMkadmi\Citadel\IpTree;

use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;

class RedisPatriciaTrieEmulator implements IpTree
{
    protected string $indexKey;

    protected string $dataKey;

    protected string $lockKey;

    protected int $lockTtl;

    protected array $cidrList;

    /**
     * @param  string  $indexKey  Redis sorted set key for CIDR end addresses
     * @param  string  $dataKey  Redis hash key for CIDR metadata (start, expires_at, meta)
     * @param  string  $lockKey  Redis key for initialization lock
     * @param  int  $lockTtl  Lock TTL (seconds)
     * @param  array  $cidrList  Initial CIDR list (cidr => metadata)
     */
    public function __construct(
        string $indexKey,
        string $dataKey,
        string $lockKey,
        int $lockTtl,
        array $cidrList
    ) {
        $this->indexKey = $indexKey;
        $this->dataKey = $dataKey;
        $this->lockKey = $lockKey;
        $this->lockTtl = $lockTtl;
        $this->cidrList = $cidrList;
    }

    /**
     * Check whether an IP is contained in the tree.
     *
     * @param  string  $ip  IPv4 address
     */
    public function containsIp(string $ip): bool
    {
        $score = $this->ipToInt($ip);
        $now = time();

        // Single pipeline with both operations
        $result = Redis::pipeline(function ($pipe) use ($score) {
            // Get closest CIDR candidate with score >= IP
            $pipe->zrevrangebyscore(
                $this->indexKey,
                $score,
                '-inf',  // Matches any score <= $score
                ['limit' => [0, 1]]
            );
            // Batch get all relevant metadata
            $pipe->hmget($this->dataKey, ['start', 'end', 'expires_at']);
        });

        $candidates = $result[0] ?? [];
        $metadata = $result[1] ?? [];

        if (empty($candidates)) {
            return false;
        }

        // Check expiration if exists
        if (! empty($metadata['expires_at']) && $now >= $metadata['expires_at']) {
            return false;
        }

        // Check IP is within CIDR range
        return $score >= ($metadata['start'] ?? PHP_INT_MAX) &&
               $score <= ($metadata['end'] ?? -1);
    }

    /**
     * Insert a CIDR block or single IP (/32) into the tree.
     *
     * @param  string  $cidrOrIp  CIDR (e.g. "1.2.3.0/24") or IP ("1.2.3.4")
     */
    public function insertIp(string $cidrOrIp): void
    {
        [$cidr, $start, $end] = $this->parseCidr($cidrOrIp);

        Redis::pipeline(function ($pipe) use ($cidr, $start, $end) {
            $pipe->zadd($this->indexKey, [$cidr => $end]);
            $pipe->hset(
                $this->dataKey,
                $cidr,
                json_encode([
                    'start' => $start,
                    'expires_at' => null,
                    'meta' => [],
                ])
            );
        });
    }

    /**
     * Bulk-load initial CIDR list with safe lock.
     */
    protected function initialize(): void
    {
        $token = (string) Str::uuid();

        $got = Redis::set(
            $this->lockKey,
            $token,
            'NX', 'EX', $this->lockTtl
        );

        if ($got) {
            Redis::pipeline(function ($pipe) {
                foreach ($this->cidrList as $cidr => $meta) {
                    [$key, $start, $end] = $this->parseCidr($cidr);
                    $pipe->zadd($this->indexKey, [$key => $end]);
                    $pipe->hset(
                        $this->dataKey,
                        $key,
                        json_encode([
                            'start' => $start,
                            'expires_at' => null,
                            'meta' => $meta,
                        ])
                    );
                }
            });

            // safe unlock
            $lua = <<<'LUA'
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
LUA;
            Redis::eval($lua, 1, $this->lockKey, $token);
        } else {
            // wait until lock is released
            while (Redis::exists($this->lockKey)) {
                usleep(100_000);
            }
        }
    }

    /**
     * Parse a CIDR or IP string into canonical CIDR and range.
     *
     * @return array [cidr, startInt, endInt]
     */
    private function parseCidr(string $cidrOrIp): array
    {
        if (strpos($cidrOrIp, '/') === false) {
            $cidrOrIp .= '/32';
        }
        [$net, $bits] = explode('/', $cidrOrIp, 2);
        $start = $this->ipToInt($net);
        $mask = (int) $bits;
        $end = $start + ((1 << (32 - $mask)) - 1);

        return [$cidrOrIp, $start, $end];
    }

    /**
     * Convert dotted-quad IPv4 to unsigned int.
     */
    private function ipToInt(string $ip): int
    {
        return (int) sprintf('%u', ip2long($ip));
    }
}
