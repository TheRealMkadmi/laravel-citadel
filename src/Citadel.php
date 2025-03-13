<?php

namespace TheRealMkadmi\Citadel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;

class Citadel
{
    /**
     * Get the fingerprint from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     */
    public function getFingerprint($request): ?string
    {
        // First check if the fingerprint is provided in headers
        $fingerprint = $request->header($this->getHeaderName());

        // If not found in headers, check cookies
        if (! $fingerprint) {
            $fingerprint = $request->cookie($this->getCookieName());
        }

        return $fingerprint;
    }

    /**
     * Get the fingerprint cookie name.
     */
    public function getCookieName(): string
    {
        return Config::get('citadel.cookie.name', 'persistentFingerprint_visitor_id');
    }

    /**
     * Get the fingerprint header name.
     */
    public function getHeaderName(): string
    {
        return Config::get('citadel.header.name', 'X-Fingerprint');
    }

    /**
     * Get the fingerprint cookie expiration in minutes.
     */
    public function getCookieExpiration(): int
    {
        return Config::get('citadel.cookie.expiration', 60 * 24 * 30);
    }

    /**
     * Check if IP address collection is enabled.
     */
    public function shouldCollectIp(): bool
    {
        return Config::get('citadel.features.collect_ip', true);
    }

    /**
     * Check if user agent collection is enabled.
     */
    public function shouldCollectUserAgent(): bool
    {
        return Config::get('citadel.features.collect_user_agent', true);
    }
}
