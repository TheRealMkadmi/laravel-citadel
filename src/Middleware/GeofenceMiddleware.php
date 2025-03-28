<?php

namespace TheRealMkadmi\Citadel\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use TheRealMkadmi\Citadel\Clients\IncolumitasApiClient;

class GeofenceMiddleware
{
    protected IncolumitasApiClient $apiClient;

    public function __construct(IncolumitasApiClient $apiClient)
    {
        $this->apiClient = $apiClient;
    }

    public function handle(Request $request, \Closure $next)
    {
        // Check if geofencing is enabled
        if (! config('citadel.geofencing.enabled')) {
            return $next($request);
        }

        // Get visitor's IP and query for location data
        $lookupResult = $this->apiClient->query($request->ip());

        // Extract the country code from the response
        $countryCode = data_get($lookupResult, 'country', null);

        // If country couldn't be determined, log warning and continue
        if (! $countryCode) {
            Log::warning('Citadel Geofencing: Could not determine country for IP: '.$request->ip());

            return $next($request);
        }

        // Get geofencing mode and countries list
        $firewallMode = config('citadel.geofencing.mode', 'block');
        $countriesList = collect(
            explode(',', config('citadel.geofencing.countries', ''))
        )->map(fn ($country) => trim($country))->filter()->values()->toArray();

        // Get the request country and check against the list
        $isCountryInList = in_array(strtoupper($countryCode), array_map('strtoupper', $countriesList));

        // Apply geofencing logic based on mode
        if ($firewallMode === 'allow') {
            // Whitelist mode: Only allow listed countries
            if (! $isCountryInList) {
                Log::info("Citadel Geofencing: Blocked request from {$countryCode} (not in allowlist)");
                abort(Response::HTTP_FORBIDDEN, 'Access denied based on geographic location');
            }
        } elseif ($firewallMode === 'block') {
            // Blacklist mode: Block listed countries
            if ($isCountryInList) {
                Log::info("Citadel Geofencing: Blocked request from {$countryCode} (in blocklist)");
                abort(Response::HTTP_FORBIDDEN, 'Access denied based on geographic location');
            }
        } else {
            Log::error("Invalid firewall mode: {$firewallMode}");
            throw new \InvalidArgumentException("Invalid citadel firewall mode: {$firewallMode}");
        }

        // Country passed the geofence check
        return $next($request);
    }
}
