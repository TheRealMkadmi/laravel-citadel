# Laravel Citadel Documentation

## Introduction

Laravel Citadel is a passive surveillance package designed to protect your public-facing endpoints. It provides a robust firewall system that analyzes incoming requests, detects anomalies, and blocks malicious traffic. The package is highly configurable and integrates seamlessly with Laravel applications.

---

## Installation

1. Install the package via Composer:

```bash
composer require therealmkadmi/laravel-citadel
```

2. Publish the configuration file:

```bash
php artisan vendor:publish --provider="TheRealMkadmi\\Citadel\\CitadelServiceProvider"
```

3. Add the middleware to your routes or global middleware stack as needed.

---

## Configuration

The configuration file is located at `config/citadel.php`. Below are the available settings:

### General Settings
- **version**: Current version of Laravel Citadel.

### Geofencing Settings
- **enabled**: Enable or disable geofencing.
- **mode**: `allow` (whitelist) or `block` (blacklist).
- **countries**: Comma-separated ISO-3166-1 alpha-2 country codes.

### Device Analyzer Settings
- **smartphone_score**: Score for smartphone devices.
- **tablet_score**: Score for tablet devices.
- **desktop_score**: Score for desktop devices.
- **bot_score**: Score for bots or automated tools.

### IP Analyzer Settings
- **weights**: Weights for different IP characteristics (e.g., `bogon`, `datacenter`, `tor`, etc.).

### Burstiness Analyzer Settings
- **min_interval**: Minimum interval between requests (in milliseconds).
- **window_size**: Sliding window size (in milliseconds).
- **max_requests_per_window**: Maximum requests allowed in the window.

### Payload Analyzer Settings
- **required_fields**: Fields required in the payload.
- **max_size**: Maximum payload size (in bytes).
- **max_params**: Maximum number of parameters allowed.
- **suspicious_patterns**: Patterns to detect malicious payloads.

### Spamminess Analyzer Settings
- **weights**: Weights for spam-related anomalies (e.g., gibberish text, repetitive content).

### Ban Settings
- **ban_ttl**: Default time-to-live for bans (in seconds).
- **cache_key**: Key prefix for storing banned IPs or fingerprints.
- **message**: Message displayed to banned users.

### API Settings
- **enabled**: Enable or disable API endpoints.
- **token**: Secret token for API authentication.
- **prefix**: Prefix for API routes.

---

## Middleware

### ProtectRouteMiddleware
Analyzes incoming requests using registered analyzers and blocks requests exceeding the configured threshold.

### ApiAuthMiddleware
Authenticates API requests using a token.

### GeofenceMiddleware
Blocks requests based on geographical location.

### BanMiddleware
Checks if a request originates from a banned IP or fingerprint.

---

## Analyzers

### BurstinessAnalyzer
Detects rapid consecutive requests and suspicious patterns in request timing.

### DeviceAnalyzer
Analyzes the User-Agent header to determine the type of device making the request.

### IpAnalyzer
Analyzes the IP address for characteristics like being a datacenter, Tor exit node, or VPN.

### PayloadAnalyzer
Analyzes the request payload for anomalies, missing fields, and malicious patterns.

### SpamminessAnalyzer
Detects spam-like behavior in request payloads.

---

## API Endpoints

### Ban Endpoint
**POST** `/api/citadel/ban`

**Parameters:**
- `identifier` (string, required): The IP or fingerprint to ban.
- `type` (string, required): `ip` or `fingerprint`.
- `duration` (integer, optional): Duration of the ban in minutes.

**Response:**
- `success` (boolean): Whether the operation was successful.
- `message` (string): Description of the result.

### Unban Endpoint
**POST** `/api/citadel/unban`

**Parameters:**
- `identifier` (string, required): The IP or fingerprint to unban.
- `type` (string, required): `ip` or `fingerprint`.

**Response:**
- `success` (boolean): Whether the operation was successful.
- `message` (string): Description of the result.

### Status Endpoint
**GET** `/api/citadel/status`

**Response:**
- `status` (string): `ok` if the API is accessible.
- `version` (string): Current version of the package.
- `timestamp` (string): Current server timestamp.

---

## Commands

### CitadelBanCommand
Bans a user by IP or fingerprint from the command line.

**Usage:**
```bash
php artisan citadel:ban {identifier} --type={ip|fingerprint|auto} --duration={minutes}
```

### CitadelUnbanCommand
Unbans a user by IP or fingerprint from the command line.

**Usage:**
```bash
php artisan citadel:unban {identifier} --type={ip|fingerprint|auto}
```

### CitadelCommand
Displays general information about the Citadel package.

**Usage:**
```bash
php artisan laravel-citadel
```

---

## Usage Examples

### Protecting Routes
Add the `citadel-protect` middleware group to your routes:

```php
Route::middleware(['citadel-protect'])->group(function () {
    Route::get('/protected', function () {
        return 'This route is protected by Citadel.';
    });
});
```

### Using the API
Enable the API in the configuration file and set a token:

```php
'api' => [
    'enabled' => true,
    'token' => env('CITADEL_API_TOKEN', 'your-secret-token'),
    'prefix' => 'api/citadel',
],
```

Make a request to ban an IP:

```bash
curl -X POST \
     -H "Authorization: Bearer your-secret-token" \
     -d "identifier=192.168.1.1&type=ip&duration=60" \
     http://your-app.test/api/citadel/ban
```

### Customizing Analyzers
You can create custom analyzers by implementing the `IRequestAnalyzer` interface and registering them in the service provider.

---

## Logging

Citadel logs various events, such as bans, unbans, and detected threats. You can configure the log channel in the `citadel.php` configuration file.

---

## Testing

Run the test suite using PHPUnit:

```bash
vendor/bin/phpunit
```

---

## Contributing

Contributions are welcome! Please follow the Laravel coding standards and submit a pull request.

---

## License

Laravel Citadel is open-sourced software licensed under the [MIT license](LICENSE.md).
