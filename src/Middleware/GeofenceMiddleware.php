<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\Enums\GeofencingMode;

class GeofenceMiddleware
{
    /**
     * Country header names to check.
     */
    private const COUNTRY_HEADERS = [
        'HTTP_CF_IPCOUNTRY',
        'X-Country-Code',
        'GEOIP_COUNTRY_CODE',
    ];

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        // Skip geofencing if not enabled or if active middleware is disabled
        if (! Config::get(CitadelConfig::KEY_MIDDLEWARE_ACTIVE_ENABLED, true) ||
            ! Config::get(CitadelConfig::KEY_GEOFENCING_ENABLED, false)) {
            return $next($request);
        }

        // Get country code from request headers
        $countryCode = $this->getCountryCode($request);

        // If country code couldn't be determined, allow the request
        if (! $countryCode) {
            Log::info('Citadel Geofencing: Unable to determine country, allowing request');

            return $next($request);
        }

        // Get the configured list of countries
        $countriesList = $this->getCountriesList();

        // No countries configured, allow all requests
        if (empty($countriesList)) {
            return $next($request);
        }

        // Check if the country is in the configured list
        $isCountryInList = in_array($countryCode, $countriesList);

        // Get the configured mode using the enum
        $modeString = Config::get(CitadelConfig::KEY_GEOFENCING_MODE, GeofencingMode::BLOCK->value);
        $firewallMode = GeofencingMode::fromString($modeString);

        if ($firewallMode === GeofencingMode::ALLOW) {
            // Allowlist mode: Only allow listed countries
            if (! $isCountryInList) {
                Log::info('Citadel Geofencing: Blocked request from {country} (not in allowlist)', [
                    'country' => $countryCode,
                ]);

                return $this->denyAccess();
            }
        } elseif ($firewallMode === GeofencingMode::BLOCK) {
            // Blocklist mode: Block listed countries
            if ($isCountryInList) {
                Log::info('Citadel Geofencing: Blocked request from {country} (in blocklist)', [
                    'country' => $countryCode,
                ]);

                return $this->denyAccess();
            }
        } else {
            Log::error('Invalid firewall mode: {mode}', ['mode' => $modeString]);
            throw new \InvalidArgumentException("Invalid citadel firewall mode: {$modeString}", 500);
        }

        // Country passed the geofence check
        return $next($request);
    }

    /**
     * Get the country code from the request.
     */
    protected function getCountryCode(Request $request): ?string
    {
        $countryCode = null;

        // Check common headers for country code
        foreach (self::COUNTRY_HEADERS as $header) {
            if ($request->server($header)) {
                $countryCode = $request->server($header);
                break;
            }
        }

        // Check if we have a country code and format it
        if ($countryCode) {
            // Ensure uppercase alpha-2 country code format
            return Str::upper($countryCode);
        }

        return null;
    }

    /**
     * Get the list of countries from configuration.
     */
    protected function getCountriesList(): array
    {
        $countries = Config::get(CitadelConfig::KEY_GEOFENCING_COUNTRIES, '');

        if (empty($countries)) {
            return [];
        }

        // Return as array of uppercase country codes
        return collect(explode(',', $countries))
            ->map(fn ($country) => Str::upper(trim($country)))
            ->filter()
            ->toArray();
    }

    /**
     * Return a forbidden response.
     */
    protected function denyAccess(): Response
    {
        return response()->json(['error' => 'Access denied based on geographic location'], Response::HTTP_FORBIDDEN);
    }
}
