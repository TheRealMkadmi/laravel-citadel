<?php

namespace TheRealMkadmi\Citadel\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class CitadelUnbanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    public $signature = 'citadel:unban {identifier : The IP address or fingerprint to unban} {--type=auto : The type of identifier: ip, fingerprint, or auto}';

    /**
     * The console command description.
     *
     * @var string
     */
    public $description = 'Unban a previously banned user by IP address or fingerprint';

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

        // Determine if the identifier is an IP or fingerprint if auto detection is enabled
        if ($type === 'auto') {
            $type = $this->detectIdentifierType($identifier);
            $this->info("Detected identifier type: {$type}");
        }

        // Validate the identifier type
        if (!in_array($type, ['ip', 'fingerprint'])) {
            $this->error("Invalid identifier type: {$type}. Must be 'ip', 'fingerprint', or 'auto'.");
            return self::FAILURE;
        }

        // Generate the ban key
        $banKey = $this->generateBanKey($type, $identifier);

        // Check if the ban exists
        if (!$this->dataStore->hasValue($banKey)) {
            $this->warn("No active ban found for {$type}: {$identifier}");
            return self::FAILURE;
        }

        // Remove the ban
        $result = $this->dataStore->removeValue($banKey);

        if ($result) {
            $this->info("Successfully unbanned {$type}: {$identifier}");
            Log::info("Citadel: User unbanned by {$type}", [
                'identifier' => $identifier,
                'ban_key' => $banKey,
            ]);
            return self::SUCCESS;
        } else {
            $this->error("Failed to unban {$type}: {$identifier}");
            return self::FAILURE;
        }
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