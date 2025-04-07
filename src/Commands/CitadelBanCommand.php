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

        \Log::info('CitadelBanCommand: Executing ban command', [
            'identifier' => $identifier,
            'type_option' => $typeString,
            'duration' => $duration ?? 'permanent',
            'reason' => $reason
        ]);

        // Resolve ban type using our enum
        $banType = $typeString === 'auto'
            ? BanType::detectType('auto', true, $identifier) // Auto-detect based on identifier
            : BanType::tryFrom($typeString);

        // Validate the type
        if ($banType === null) {
            \Log::error('CitadelBanCommand: Invalid identifier type specified', [
                'specified_type' => $typeString,
                'valid_types' => BanType::getValues()
            ]);
            
            $this->error("Invalid identifier type: {$typeString}");
            $this->line('Valid types are: '.implode(', ', BanType::getValues()));

            return Command::FAILURE;
        }

        \Log::info('CitadelBanCommand: Resolved ban type', [
            'identifier' => $identifier,
            'resolved_type' => $banType->value,
            'was_autodetected' => $typeString === 'auto'
        ]);

        // Generate ban key
        $key = $this->generateBanKey($identifier, $banType->value);

        // Create ban record
        $banData = [
            'timestamp' => now()->timestamp,
            'reason' => $reason,
            'type' => $banType->value,
        ];

        \Log::debug('CitadelBanCommand: Generated ban record data', [
            'key' => $key,
            'identifier' => $identifier,
            'type' => $banType->value,
            'timestamp' => $banData['timestamp'],
        ]);

        // Check if ban already exists
        $existingBan = $this->dataStore->getValue($key);
        if ($existingBan !== null) {
            \Log::info('CitadelBanCommand: Overwriting existing ban record', [
                'identifier' => $identifier,
                'type' => $banType->value,
                'previous_reason' => $existingBan['reason'] ?? 'unknown',
                'new_reason' => $reason,
            ]);
            
            $this->warn("Note: Overwriting existing ban for {$banType->value} '{$identifier}'");
        }

        // Store ban record
        if ($duration !== null) {
            $success = $this->dataStore->setValue($key, $banData, (int) $duration);
            
            if ($success) {
                \Log::info('CitadelBanCommand: Successfully banned identifier with expiry', [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'duration_seconds' => (int) $duration,
                    'expires_at' => now()->addSeconds((int) $duration)->toDateTimeString(),
                ]);
                
                $this->info("Banned {$banType->value} '{$identifier}' for {$duration} seconds");
                $this->line("Reason: {$reason}");
                $this->line("Expires: " . now()->addSeconds((int) $duration)->format('Y-m-d H:i:s'));
            } else {
                \Log::error('CitadelBanCommand: Failed to store ban record', [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'data_store' => get_class($this->dataStore),
                ]);
                
                $this->error("Failed to ban {$banType->value} '{$identifier}'");
                return Command::FAILURE;
            }
        } else {
            // Use a very long TTL for permanent ban (10 years)
            $permanentDuration = 10 * 365 * 24 * 60 * 60;
            $success = $this->dataStore->setValue($key, $banData, $permanentDuration);
            
            if ($success) {
                \Log::info('CitadelBanCommand: Successfully applied permanent ban', [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'ttl_years' => 10,
                ]);
                
                $this->info("Permanently banned {$banType->value} '{$identifier}'");
                $this->line("Reason: {$reason}");
            } else {
                \Log::error('CitadelBanCommand: Failed to store permanent ban record', [
                    'identifier' => $identifier,
                    'type' => $banType->value,
                    'data_store' => get_class($this->dataStore),
                ]);
                
                $this->error("Failed to ban {$banType->value} '{$identifier}'");
                return Command::FAILURE;
            }
        }

        return Command::SUCCESS;
    }

    /**
     * Generate a ban key for the identifier.
     */
    protected function generateBanKey(string $identifier, string $type): string
    {
        $safeIdentifier = Str::slug($identifier);
        $prefix = Config::get(CitadelConfig::KEY_BAN.'.cache_key', 'ban');

        return "{$prefix}:{$type}:{$safeIdentifier}";
    }
}
