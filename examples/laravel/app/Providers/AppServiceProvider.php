<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use OpenPasskey\Server\CredentialStore;
use App\TmpCredentialStore;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(CredentialStore::class, TmpCredentialStore::class);
    }

    public function boot(): void {}
}
