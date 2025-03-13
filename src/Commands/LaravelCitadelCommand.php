<?php

namespace TheRealMkadmi\LaravelCitadel\Commands;

use Illuminate\Console\Command;

class LaravelCitadelCommand extends Command
{
    public $signature = 'laravel-citadel';

    public $description = 'My command';

    public function handle(): int
    {
        $this->comment('All done');

        return self::SUCCESS;
    }
}
