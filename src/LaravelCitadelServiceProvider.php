<?php

namespace TheRealMkadmi\LaravelCitadel;

use Illuminate\Http\Request;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use TheRealMkadmi\LaravelCitadel\Commands\LaravelCitadelCommand;
use TheRealMkadmi\LaravelCitadel\Components\Fingerprint;
use Spatie\LaravelPackageTools\Commands\InstallCommand;

class LaravelCitadelServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('laravel-citadel')
            ->hasConfigFile()
            ->hasAssets()
            ->hasViewComponents('citadel', Fingerprint::class)
            ->hasCommand(LaravelCitadelCommand::class)
            ->publishesServiceProvider(LaravelCitadelServiceProvider::class)
            ->hasInstallCommand(function (InstallCommand $command) {
                $command
                    ->startWith(function (InstallCommand $command) {
                        $command->info('Installing Laravel Citadel...');
                    })
                    ->publishConfigFile()
                    ->publishAssets()
                    ->publishMigrations()
                    ->askToRunMigrations()
                    ->copyAndRegisterServiceProviderInApp()
                    ->askToStarRepoOnGitHub('therealmkadmi/laravel-citadel')
                    ->endWith(function (InstallCommand $command) {
                        $command->info('Laravel Citadel installed successfully!');
                    });
            });
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function packageBooted()
    {
        // Register the getFingerprint macro on the Request class
        Request::macro('getFingerprint', function () {
            return app(LaravelCitadel::class)->getFingerprint($this);
        });
    }
}
