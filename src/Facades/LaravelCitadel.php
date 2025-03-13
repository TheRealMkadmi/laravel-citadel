<?php

namespace TheRealMkadmi\LaravelCitadel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \TheRealMkadmi\LaravelCitadel\LaravelCitadel
 */
class LaravelCitadel extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \TheRealMkadmi\LaravelCitadel\LaravelCitadel::class;
    }
}
