<?php

namespace TheRealMkadmi\Citadel\Events;

use Illuminate\Broadcasting\Channel;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Broadcasting\ShouldBroadcastNow;
use Illuminate\Queue\SerializesModels;

class BlacklistUpdated implements ShouldBroadcastNow
{
    use InteractsWithSockets, SerializesModels;

    public string $type;

    public string $value;

    public function __construct(string $type, string $value)
    {
        $this->type = $type;
        $this->value = $value;
    }

    public function broadcastOn(): Channel
    {
        return new Channel(config('ip-tree.broadcast_channel'));
    }

    public function broadcastWith(): array
    {
        return ['type' => $this->type, 'value' => $this->value];
    }
}
