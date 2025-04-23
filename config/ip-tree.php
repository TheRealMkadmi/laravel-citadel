<?php

return [
    /*
     |--------------------------------------------------------------------------
     | IpTree Driver
     |--------------------------------------------------------------------------
     |
     | Choose which implementation to use for your Patricia tree:
     | - redis:   use Redis pub/sub + redis sets
     | - ffi:     use native C library via PHP‑FFI
     */
    'driver' => env('CITADEL_IPTREE_DRIVER', 'redis'),

    /*
     |--------------------------------------------------------------------------
     | Broadcast Channel
     |--------------------------------------------------------------------------
     |
     | The private or presence channel used for propagating blacklist updates.
     */
    'broadcast_channel' => env('CITADEL_BROADCAST_CHANNEL', 'citadel-blacklist'),
];