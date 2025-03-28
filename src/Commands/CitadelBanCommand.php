<?php

namespace TheRealMkadmi\Citadel\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class CitadelBanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    public $signature = 'citadel:ban {identifier : The IP address or fingerprint to ban} {--type=auto : The type of identifier: ip, fingerprint, or auto} {--duration= : Optional ban duration in minutes (permanent if not specified)}';

    /**
     * The console command description.
     *
     * @var string
     */
    public $description = 'Ban a user by IP address or fingerprint';

    /**
     * The data store instance.
     *
     * @var \TheRealMkadmi\Citadel\DataStore\DataStore
     */
    protected DataStore $dataStore;

    /**
     * The prefix used for ban cache keys.
     *
     * @var string
     */
    protected string $banKeyPrefix;

    /**
     * Create a new command instance.
     *
     * @param \TheRealMkadmi\Citadel\DataStore\DataStore $dataStore
     * @return void
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct();

        $this->dataStore = $dataStore;
        $this->banKeyPrefix = config('citadel.cache.key_prefix', 'citadel:') . config('citadel.ban.cache_key', 'banned');
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $identifier = $this->argument('identifier');
        $type = $this->option('type');
        $duration = $this->option('duration');

        // Determine if the identifier is an IP or fingerprint if auto detection is enabled
        if ($type === 'auto') {
            $type = $this->detectIdentifierType($identifier);
        }

        // Validate the identifier type
        if (!in_array($type, ['ip', 'fingerprint'])) {
            $this->error("Invalid identifier type: {$type}. Must be 'ip', 'fingerprint', or 'auto'.");
            return self::FAILURE;
        }

        // Validate the identifier based on its type
        if (!$this->validateIdentifier($identifier, $type)) {
            $this->error("Invalid {$type} format: {$identifier}");
            return self::FAILURE;
        }

        // Calculate TTL (null for permanent ban)
        $ttl = $duration ? (int) $duration * 60 : config('citadel.ban.ban_ttl');

        // Generate the ban key and store it
        $banKey = $this->generateBanKey($type, $identifier);
        $this->dataStore->setValue($banKey, true, $ttl);

        // Log the action
        $durationText = $ttl ? "for {$duration} minutes" : "permanently";
        $this->info("User {$durationText} banned by {$type}: {$identifier}");
        Log::info("Citadel: User banned by {$type}", [
            'identifier' => $identifier,
            'duration' => $durationText,
            'ban_key' => $banKey,
        ]);

        return self::SUCCESS;
    }

    /**
     * Detect the type of identifier (IP or fingerprint).
     *
     * @param string $identifier
     * @return string
     */
    protected function detectIdentifierType(string $identifier): string
    {
        // Simple check if the identifier looks like an IP address
        if (filter_var($identifier, FILTER_VALIDATE_IP)) {
            return 'ip';
        }

        // Otherwise assume it's a fingerprint
        return 'fingerprint';
    }

    /**
     * Validate the identifier based on its type.
     *
     * @param string $identifier
     * @param string $type
     * @return bool
     */
    protected function validateIdentifier(string $identifier, string $type): bool
    {
        if ($type === 'ip') {
            return filter_var($identifier, FILTER_VALIDATE_IP) !== false;
        } elseif ($type === 'fingerprint') {
            // Simple validation for fingerprint (non-empty string)
            return !empty(trim($identifier));
        }

        return false;
    }

    /**
     * Generate a cache key for banned items.
     *
     * @param string $type The type of ban (ip or fingerprint)
     * @param string $value The value to check (ip address or fingerprint)
     * @return string
     */
    protected function generateBanKey(string $type, string $value): string
    {
        return "{$this->banKeyPrefix}:{$type}:{$value}";
    }
}