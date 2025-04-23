<?php

namespace TheRealMkadmi\Citadel\IpTree;

interface IpTree
{
    /**
     * Insert a CIDR block or single IP into the tree.
     * A plain IPv4 address (no slash) is treated as /32.
     *
     * @param  string  $cidrOrIp  CIDR (e.g. "1.2.3.0/24") or exact IP ("1.2.3.4")
     */
    public function insertIp(string $ip): void;

    /**
     * Check whether an IP is contained in the tree.
     */
    public function containsIp(string $ip): bool;
}
