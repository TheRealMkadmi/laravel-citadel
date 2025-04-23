<?php

namespace TheRealMkadmi\Citadel\Listeners;

use TheRealMkadmi\Citadel\Events\BlacklistUpdated;
use TheRealMkadmi\Citadel\IpTree\IpTree;
use TheRealMkadmi\Citadel\DataStore\DataStore;

class HandleBlacklistUpdate
{
    public function handle(BlacklistUpdated $event)
    {
        if ($event->type === 'ip') {
            app(IpTree::class)->insertIp($event->value);
        } else {
            app(DataStore::class)->setValue("banned:fp:{$event->value}", ['timestamp' => now()->timestamp], null);
        }
    }
}