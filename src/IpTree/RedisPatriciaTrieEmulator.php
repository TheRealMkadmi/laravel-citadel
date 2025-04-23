<?php

namespace TheRealMkadmi\Citadel\IpTree;

use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;

class RedisPatriciaTrieEmulator implements IpTree
{
    protected string $streamKey;
    protected string $childMapKey;
    protected string $metaMapKey;
    protected string $lockKey;
    protected int    $lockTtl;
    protected array  $cidrList;

    /**
     * @param string $streamKey    Redis Stream key for trie nodes
     * @param string $childMapKey  Redis hash key mapping "parentId:bit" => childId
     * @param string $metaMapKey   Redis hash key mapping nodeId => JSON metadata
     * @param string $lockKey      Redis key for initialization lock
     * @param int    $lockTtl      Lock TTL in seconds
     * @param array  $cidrList     Initial CIDR list (cidr => metadata)
     */
    public function __construct(
        string $streamKey,
        string $childMapKey,
        string $metaMapKey,
        string $lockKey,
        int    $lockTtl,
        array  $cidrList
    ) {
        $this->streamKey    = $streamKey;
        $this->childMapKey  = $childMapKey;
        $this->metaMapKey   = $metaMapKey;
        $this->lockKey      = $lockKey;
        $this->lockTtl      = $lockTtl;
        $this->cidrList     = $cidrList;
    }

    /**
     * Insert a CIDR block or single IP (/32) into the trie.
     *
     * @param string $cidrOrIp CIDR (e.g., "1.2.3.0/24") or IP ("1.2.3.4")
     */
    public function insertIp(string $cidrOrIp): void
    {
        [$cidr, $start, $end, $mask] = $this->parseCidr($cidrOrIp);
        $parentId = '0-0';

        for ($depth = 1; $depth <= $mask; $depth++) {
            $bit    = ($start >> (32 - $depth)) & 1;
            $mapKey = $parentId . ':' . $bit;
            $childId = Redis::hget($this->childMapKey, $mapKey);

            if (! $childId) {
                $childId = Redis::xadd(
                    $this->streamKey,
                    '*',
                    ['bit'    => (string)$bit, 'parent' => $parentId]
                );
                Redis::hset($this->childMapKey, $mapKey, $childId);
            }
            $parentId = $childId;
        }

        $meta = json_encode([
            'cidr'       => $cidr,
            'start'      => $start,
            'end'        => $end,
            'expires_at' => null,
            'meta'       => []
        ]);
        Redis::hset($this->metaMapKey, $parentId, $meta);
    }

    /**
     * Check whether an IP is contained in the trie via single Redis roundtrip.
     *
     * @param string $ip IPv4 address
     * @return bool
     */
    public function containsIp(string $ip): bool
    {
        $ipInt = $this->ipToInt($ip);
        $now   = time();

        // Ensure initialization
        if (! Redis::exists($this->streamKey . ':initialized')) {
            $this->initialize();
        }

        // Single-roundtrip Lua script to traverse childMap and fetch metadata
        $lua = <<<'LUA'
local childMap = KEYS[1]
local metaMap  = KEYS[2]
local ip       = tonumber(ARGV[1])
local now      = tonumber(ARGV[2])
local parent   = '0-0'
for d = 1, 32 do
  local shift = 32 - d
  local bit = shift > 0 and math.floor(ip / (2^shift)) % 2 or ip % 2
  local key = parent .. ':' .. bit
  local child = redis.call('HGET', childMap, key)
  if not child or child == '' then break end
  parent = child
end
local raw = redis.call('HGET', metaMap, parent)
if not raw or raw == '' then return 0 end
local info = cjson.decode(raw)
if info.expires_at and now >= tonumber(info.expires_at) then return 0 end
if ip >= tonumber(info.start) and ip <= tonumber(info["end"]) then
  return 1
else
  return 0
end
LUA;

        return (bool) Redis::eval(
            $lua,
            2,
            $this->childMapKey,
            $this->metaMapKey,
            $ipInt,
            $now
        );
    }

    /**
     * Bulk-load initial CIDRs with safe lock.
     */
    protected function initialize(): void
    {
        $token = (string) Str::uuid();
        $got   = Redis::set($this->lockKey, $token, 'NX', 'EX', $this->lockTtl);

        if ($got) {
            foreach ($this->cidrList as $cidr => $meta) {
                $this->insertIp($cidr);
                if (isset($meta['expires_at'])) {
                    list($_cidr, $start, $end, $mask) = $this->parseCidr($cidr);
                    $parentId = '0-0';
                    for ($i = 1; $i <= $mask; $i++) {
                        $bit      = ($start >> (32 - $i)) & 1;
                        $parentId = Redis::hget($this->childMapKey, $parentId . ':' . $bit);
                    }
                    $entry = json_decode(Redis::hget($this->metaMapKey, $parentId), true);
                    $entry['expires_at'] = $meta['expires_at'];
                    Redis::hset($this->metaMapKey, $parentId, json_encode($entry));
                }
            }
            Redis::set($this->streamKey . ':initialized', 1);

            $unlockLua = <<<'LUA'
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
LUA;
            Redis::eval($unlockLua, 1, $this->lockKey, $token);
        } else {
            while (Redis::exists($this->lockKey)) {
                usleep(100_000);
            }
        }
    }

    /**
     * Parse an IP or CIDR into canonical form, start/end and mask.
     *
     * @return array [cidr, start, end, mask]
     */
    private function parseCidr(string $cidrOrIp): array
    {
        if (strpos($cidrOrIp, '/') === false) {
            $cidrOrIp .= '/32';
        }
        [$net, $bits] = explode('/', $cidrOrIp, 2);
        $start = $this->ipToInt($net);
        $mask  = (int)$bits;
        $end   = $start + ((1 << (32 - $mask)) - 1);
        return [$cidrOrIp, $start, $end, $mask];
    }

    /**
     * Convert dotted-quad IPv4 to unsigned int.
     */
    private function ipToInt(string $ip): int
    {
        return (int) sprintf('%u', ip2long($ip));
    }
}
