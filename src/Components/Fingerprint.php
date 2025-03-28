<?php

namespace TheRealMkadmi\Citadel\Components;

use Illuminate\View\Component;
use Illuminate\View\View;

class Fingerprint extends Component
{
    /**
     * Whether to include the automatic initialization script.
     */
    public bool $autoInit;

    /**
     * The cookie expiration time in minutes.
     */
    public int $expiration;

    /**
     * The cookie name.
     */
    public string $cookieName;

    /**
     * The header name.
     */
    public string $headerName;

    /**
     * Create a new component instance.
     */
    public function __construct(
        bool $autoInit = true,
        ?int $expiration = null,
        ?string $cookieName = null,
        ?string $headerName = null
    ) {
        $this->autoInit = $autoInit;
        $this->expiration = $expiration ?? config('citadel.cookie.expiration', 60 * 24 * 30); // 30 days in minutes
        $this->cookieName = $cookieName ?? config('citadel.cookie.name', 'persistentFingerprint_visitor_id');
        $this->headerName = $headerName ?? config('citadel.header.name', 'X-Fingerprint');
    }

    /**
     * Get the view / contents that represent the component.
     */
    public function render(): View
    {
        return view('citadel::fingerprint');
    }
}
