<?php

namespace TheRealMkadmi\LaravelCitadel;

class LaravelCitadel
{
    /**
     * The key name for the fingerprint cookie.
     *
     * @var string
     */
    protected $cookieName = 'persistentFingerprint_visitor_id';

    /**
     * The key name for the fingerprint header.
     *
     * @var string
     */
    protected $headerName = 'X-Fingerprint';

    /**
     * Get the fingerprint from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    public function getFingerprint($request)
    {
        // First check if the fingerprint is provided in headers
        $fingerprint = $request->header($this->headerName);

        // If not found in headers, check cookies
        if (! $fingerprint) {
            $fingerprint = $request->cookie($this->cookieName);
        }

        return $fingerprint;
    }

    /**
     * Get the fingerprint cookie name.
     *
     * @return string
     */
    public function getCookieName()
    {
        return $this->cookieName;
    }

    /**
     * Get the fingerprint header name.
     *
     * @return string
     */
    public function getHeaderName()
    {
        return $this->headerName;
    }
}
