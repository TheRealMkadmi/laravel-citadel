<?php

declare(strict_types=1);

namespace TheRealMkadmi\Citadel\Clients;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class IncolumitasApiClient
{
    /**
     * API base URL.
     */
    protected string $baseUrl = 'https://api.incolumitas.com/';

    /**
     * API timeout in seconds.
     */
    protected int $timeout = 3;

    /**
     * Whether to retry failed requests.
     */
    protected bool $retry = true;

    /**
     * Maximum number of retries.
     */
    protected int $maxRetries = 1;

    /**
     * Delay between retries in milliseconds.
     */
    protected int $retryDelay = 500;

    /**
     * Create a new API client instance.
     */
    public function __construct(array $config = [])
    {
        // Override defaults with provided configuration
        if (isset($config['base_url'])) {
            $this->baseUrl = $config['base_url'];
        }

        if (isset($config['timeout'])) {
            $this->timeout = (int) $config['timeout'];
        }

        if (isset($config['retry'])) {
            $this->retry = (bool) $config['retry'];
        }

        if (isset($config['max_retries'])) {
            $this->maxRetries = (int) $config['max_retries'];
        }

        if (isset($config['retry_delay'])) {
            $this->retryDelay = (int) $config['retry_delay'];
        }
    }

    /**
     * Check if an IP address has certain characteristics.
     *
     * @param  string  $ip  The IP address to check
     * @return array|null API response data or null on failure
     */
    public function checkIp(string $ip): ?array
    {
        try {
            $response = $this->createRequest()
                ->get("ip/{$ip}");

            if ($response->successful()) {
                return $response->json();
            }

            $this->logApiError('IP check failed', $response->status(), $response->body(), ['ip' => $ip]);

            return null;
        } catch (ConnectionException|RequestException $e) {
            $this->logApiException('IP check error', $e, ['ip' => $ip]);

            return null;
        }
    }

    /**
     * Create a configured HTTP client.
     */
    protected function createRequest(): PendingRequest
    {
        $request = Http::baseUrl($this->baseUrl)
            ->timeout($this->timeout)
            ->acceptJson()
            ->withUserAgent('Laravel-Citadel/'.config('citadel.version', '1.1.0'));

        if ($this->retry) {
            $request->retry($this->maxRetries, $this->retryDelay);
        }

        return $request;
    }

    /**
     * Log API errors with consistent formatting.
     */
    protected function logApiError(string $message, int $status, string $response, array $context = []): void
    {
        Log::channel(config('citadel.log_channel', 'stack'))
            ->error("Citadel API: {$message}", array_merge([
                'status' => $status,
                'response' => $response,
            ], $context));
    }

    /**
     * Log exceptions with consistent formatting.
     */
    protected function logApiException(string $message, \Exception $exception, array $context = []): void
    {
        Log::channel(config('citadel.log_channel', 'stack'))
            ->error("Citadel API: {$message}", array_merge([
                'exception' => $exception->getMessage(),
                'trace' => $exception->getTraceAsString(),
            ], $context));
    }
}
