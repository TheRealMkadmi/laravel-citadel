<?php

namespace TheRealMkadmi\Citadel\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Orchestra\Testbench\TestCase as Orchestra;
use TheRealMkadmi\Citadel\CitadelServiceProvider;
use Orchestra\Testbench\Concerns\WithWorkbench; 

class TestCase extends Orchestra
{
    use WithWorkbench; 
    protected $enablesPackageDiscoveries = true; 

    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app)
    {
        return [
            CitadelServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app)
    {

    }
}
