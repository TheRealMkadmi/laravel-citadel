<?php

namespace TheRealMkadmi\Citadel\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use TheRealMkadmi\Citadel\Config\CitadelConfig;
use TheRealMkadmi\Citadel\DataStore\DataStore;
use TheRealMkadmi\Citadel\Enums\BanType;

class CitadelUnbanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:unban 
                            {identifier : The IP address or fingerprint to unban}
                            {--type=auto : Type of identifier (ip, fingerprint, or auto for autodetection)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Remove a ban for an IP address or fingerprint';

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

        \Log::info('CitadelUnbanCommand: Executing unban command', [
            'identifier' => $identifier,
            'type_option' => $typeString,
        ]);

        // Resolve ban type using our enum
        $banType = $typeString === 'auto'
            ? BanType::detectType('auto', true, $identifier) // Auto-detect based on identifier
            : BanType::tryFrom($typeString);

        // Validate the type
        if ($banType === null) {
            \Log::error('CitadelUnbanCommand: Invalid identifier type specified', [
                'specified_type' => $typeString,
                'valid_types' => BanType::getValues(),
            ]);

            $this->error("Invalid identifier type: {$typeString}");
            $this->line('Valid types are: '.implode(', ', BanType::getValues()));

            return Command::FAILURE;
        }

        \Log::info('CitadelUnbanCommand: Resolved ban type', [
            'identifier' => $identifier,
            'resolved_type' => $banType->value,
            'was_autodetected' => $typeString === 'auto',
        ]);

        // Generate ban key
        $key = $this->generateBanKey($identifier, $banType->value);

        \Log::debug('CitadelUnbanCommand: Generated ban key', [
            'identifier' => $identifier,
            'type' => $banType->value,
            'key' => $key,
        ]);

        // Check if the ban exists
        $banData = $this->dataStore->getValue($key);

        if ($banData === null) {
            \Log::info('CitadelUnbanCommand: No active ban found', [
                'identifier' => $identifier,
                'type' => $banType->value,
            ]);

            $this->warn("No active ban found for {$banType->value} '{$identifier}'");

            return Command::FAILURE;
        }

        \Log::info('CitadelUnbanCommand: Found existing ban record', [
            'identifier' => $identifier,
            'type' => $banType->value,
            'banned_at' => isset($banData['timestamp']) ? date('Y-m-d H:i:s', $banData['timestamp']) : 'unknown',
            'reason' => $banData['reason'] ?? 'unknown',
        ]);

        // Remove the ban
        $success = $this->dataStore->removeValue($key);

        if ($success) {
            \Log::info('CitadelUnbanCommand: Successfully removed ban record', [
                'identifier' => $identifier,
                'type' => $banType->value,
            ]);

            $this->info("Successfully unbanned {$banType->value} '{$identifier}'");

            return Command::SUCCESS;
        } else {
            \Log::error('CitadelUnbanCommand: Failed to remove ban record', [
                'identifier' => $identifier,
                'type' => $banType->value,
                'data_store' => get_class($this->dataStore),
            ]);

            $this->error("Failed to unban {$banType->value} '{$identifier}'");

            return Command::FAILURE;
        }
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
