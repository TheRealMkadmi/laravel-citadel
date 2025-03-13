# A Passive Surveillance Package for Laravel to Protect Your Public Facing Endpoints

[![Latest Version on Packagist](https://img.shields.io/packagist/v/therealmkadmi/Laravel-citadel.svg?style=flat-square)](https://packagist.org/packages/therealmkadmi/Laravel-citadel)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/therealmkadmi/Laravel-citadel/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/therealmkadmi/Laravel-citadel/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/therealmkadmi/Laravel-citadel/fix-php-code-style-issues.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/therealmkadmi/Laravel-citadel/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/therealmkadmi/Laravel-citadel.svg?style=flat-square)](https://packagist.org/packages/therealmkadmi/Laravel-citadel)

Laravel Citadel is an advanced, real-time firewall package for Laravel designed to protect your public-facing endpoints—especially those handling critical actions such as order placement. Using Redis and Laravel Octane's in-memory caching, Laravel Citadel performs multi-faceted analysis including rate limiting, payload integrity checks, failure tracking, device fingerprint verification, and referrer validation. Its weighted scoring system dynamically flags suspicious activity, enabling you to stop malicious human or automated abuse before it reaches your business logic.

## Installation

You can install the package via Composer:

```bash
composer require therealmkadmi/laravel-citadel
```

You can publish and run the migrations with:

```bash
php artisan vendor:publish --tag="citadel-migrations"
php artisan migrate
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="citadel-config"
```

This is the contents of the published config file:

```php
return [
    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Define the maximum number of requests per minute and minimum allowed
    | time interval between orders. The firewall uses a sliding window implemented
    | with Redis sorted sets to track request frequency.
    |
    */
    'rate_limit' => [
        'window'       => 60000,  // in milliseconds (60 seconds)
        'max_requests' => 5,
        'min_interval' => 5000,   // in milliseconds (5 seconds)
        'excess_weight'=> 10,     // points per extra request
        'burst_weight' => 20,     // additional points if requests are too bursty
    ],

    /*
    |--------------------------------------------------------------------------
    | Payload Analysis
    |--------------------------------------------------------------------------
    |
    | Define required fields and parameters for payload validation. The
    | firewall analyzes payloads for missing fields, nonsensical content,
    | and extreme values. Adjust the weights to balance false positives.
    |
    */
    'payload' => [
        'required_fields' => ['name', 'table', 'items'],
        'missing_field_weight' => 30,
        'text_anomaly_weight'  => 15,
        'repetition_weight'    => 10,
        'extreme_value_weight' => 20,
        'price_mismatch_weight'=> 20,
    ],

    /*
    |--------------------------------------------------------------------------
    | Failure Tracking
    |--------------------------------------------------------------------------
    |
    | Configure how many failed attempts (due to validation or firewall blocks)
    | increase the suspect score. The failure counter uses Redis with a TTL to
    | ensure old failures decay over time.
    |
    */
    'failure' => [
        'weight_per_failure' => 5,
        'max_failures'       => 10,
        'ttl'                => 3600, // in seconds (1 hour)
    ],

    /*
    |--------------------------------------------------------------------------
    | Device Fingerprint
    |--------------------------------------------------------------------------
    |
    | Define the weights for device types. Since the typical usage involves
    | mobile devices (via QR codes), desktop or unusual User-Agents increase
    | the suspect score.
    |
    */
    'device' => [
        'desktop_weight'     => 15,
        'automation_weight'  => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Referrer Validation
    |--------------------------------------------------------------------------
    |
    | Configure valid referers. Requests originating from an unexpected domain
    | or with no referer add to the suspect score.
    |
    */
    'referrer' => [
        'expected_domain'    => env('APP_URL'),
        'missing_weight'     => 5,
        'invalid_domain_weight' => 15,
    ],

    /*
    |--------------------------------------------------------------------------
    | Overall Threshold
    |--------------------------------------------------------------------------
    |
    | The cumulative suspect score beyond which a request is considered malicious
    | and is blocked.
    |
    */
    'threshold' => 30,
];
```

Optionally, you can publish the views using:

```bash
php artisan vendor:publish --tag="citadel-views"
```

## Usage

Laravel Citadel works as a middleware. Here’s how you can integrate it into your routes:

### 1. Register the Middleware

Add the Citadel firewall middleware to your `app/Http/Kernel.php`:

```php
protected $routeMiddleware = [
    // ...
    'citadel' => \TherealMkadmi\Citadel\Middleware\CitadelFirewall::class,
];
```

### 2. Protect Critical Endpoints

Apply the middleware to your sensitive endpoints. For example, to protect the `send-order` endpoint:

```php
Route::post('/send-order', [OrderController::class, 'placeOrder'])
     ->middleware('citadel');
```

### 3. Customize Behavior

Adjust settings in `config/citadel.php` to tailor the firewall to your needs. The configuration parameters include:
- **Rate Limiting**: Set the window, maximum requests, and burst thresholds.
- **Payload Analysis**: Define required fields, entropy limits, and weights for anomalies.
- **Failure Tracking**: Control failure weights and decay time.
- **Device Fingerprint**: Set additional weights for desktop or automated User-Agents.
- **Referrer Validation**: Whitelist your domain and adjust penalties for missing or invalid referers.
- **Threshold**: Set the overall suspect score above which requests are blocked.

## How It Works

Laravel Citadel performs a series of checks on each incoming request:
1. **Real-Time Frequency Tracking**:  
   - Uses Redis sorted sets to record and analyze request timestamps.
   - Removes entries outside a 60-second window and calculates the current request rate.
   - Enforces a minimum interval between requests to prevent burstiness.

2. **Payload Anomaly Detection**:  
   - Validates that required fields (e.g., name, table, items) are present.
   - Analyzes text fields using regex and entropy calculations to detect gibberish or repetitive content.
   - Checks for extreme values and logical inconsistencies in numeric data (e.g., unrealistic quantities or price mismatches).

3. **Failure Tracking**:  
   - Tracks failed attempts via a Redis counter with a TTL.
   - Increments the suspect score for each failure, decaying over time if the user ceases suspicious activity.

4. **Device Fingerprint Analysis**:  
   - Examines the User-Agent header to determine if the request originates from a mobile device.
   - Assigns additional points for desktop browsers or known automation tools.

5. **Referrer Verification**:  
   - Validates the HTTP referer against an expected domain.
   - Penalizes requests with a missing referer or one that originates from an unauthorized domain.

6. **Weighted Scoring System**:  
   - Aggregates scores from frequency, payload, failure, device, and referrer analyses.
   - Compares the cumulative score against a configurable threshold.
   - Blocks the request if the threshold is exceeded, logging the event for further analysis.

## Testing

You can run the tests via Composer:

```bash
composer test
```

Simulate various scenarios:
- **Normal Traffic**: Ensure legitimate orders (with proper payloads and mobile devices) pass.
- **High-Frequency Abuse**: Simulate a rapid succession of orders to trigger rate limiting.
- **Payload Tampering**: Send malformed payloads to test anomaly detection.
- **Device & Referrer Variations**: Use different User-Agents and referers to verify proper scoring.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request. For larger changes, consider discussing your ideas first.

## Security Vulnerabilities

For information on reporting security vulnerabilities, contact me privately on `wahibmkadmi16 [at] gmail [dot] com`.

## Credits

- [Wahib](https://github.com/TheRealMkadmi)
- [All Contributors](../../contributors)

## License

Laravel Citadel is open-sourced software licensed under the MIT License.
