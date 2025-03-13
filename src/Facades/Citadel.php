<?php

namespace TheRealMkadmi\Citadel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \TheRealMkadmi\Citadel\Citadel
 */
class Citadel extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \TheRealMkadmi\Citadel\Citadel::class;
    }
}
