<?php

namespace TheRealMkadmi\Citadel\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\BanType;

class CitadelBanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:ban 
                            {identifier : The IP address or fingerprint to ban}
                            {--type=auto : Type of identifier (ip, fingerprint, or auto for autodetection)}
                            {--duration= : Ban duration in seconds (omit for permanent)}
                            {--reason= : Reason for the ban}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Ban an IP address or fingerprint from accessing your application';

    /**
     * The data store instance.
     */
    protected DataStore $dataStore;

    /**
     * Create a new command instance.
     */
    public function __construct(DataStore $dataStore)
    {
        parent::__construct();
        $this->dataStore = $dataStore;
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $identifier = $this->argument('identifier');
        $typeString = $this->option('type');
        $duration = $this->option('duration');
        $reason = $this->option('reason') ?? 'Manual ban via CLI';

        // Resolve ban type using our enum
        $banType = $typeString === 'auto'
            ? BanType::detectType('auto', true, $identifier) // Auto-detect based on identifier
            : BanType::tryFrom($typeString);
        
        // Validate the type
        if ($banType === null) {
            $this->error("Invalid identifier type: {$typeString}");
            $this->line("Valid types are: " . implode(', ', BanType::getValues()));
            return Command::FAILURE;
        }

        // Generate ban key
        $key = $this->generateBanKey($identifier, $banType->value);

        // Create ban record
        $banData = [
            'timestamp' => now()->timestamp,
            'reason' => $reason,
            'type' => $banType->value,
        ];

        // Store ban record
        if ($duration !== null) {
            $this->dataStore->setValue($key, $banData, (int) $duration);
            $this->info("Banned {$banType->value} '{$identifier}' for {$duration} seconds");
            $this->line("Reason: {$reason}");
        } else {
            // Use a very long TTL for permanent ban (10 years)
            $this->dataStore->setValue($key, $banData, 10 * 365 * 24 * 60 * 60);
            $this->info("Permanently banned {$banType->value} '{$identifier}'");
            $this->line("Reason: {$reason}");
        }

        return Command::SUCCESS;
    }

    /**
     * Generate a ban key for the identifier.
     */
    protected function generateBanKey(string $identifier, string $type): string
    {
        $safeIdentifier = Str::slug($identifier);
        $prefix = Config::get(CitadelConfig::KEY_BAN . '.cache_key', 'ban');

        return "{$prefix}:{$type}:{$safeIdentifier}";
    }
}
