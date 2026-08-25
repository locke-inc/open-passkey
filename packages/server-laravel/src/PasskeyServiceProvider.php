<?php

declare(strict_types=1);

namespace OpenPasskey\Laravel;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use OpenPasskey\Server\CredentialStore;
use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;

class PasskeyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/config/passkey.php', 'passkey');

        $this->app->singleton(PasskeyConfig::class, function ($app) {
            if (!$app->bound(CredentialStore::class)) {
                throw new PasskeyError('CredentialStore not bound — bind your own implementation in a service provider', 500);
            }

            return new PasskeyConfig(
                rpId: config('passkey.rp_id', 'localhost'),
                rpDisplayName: config('passkey.rp_display_name', 'My App'),
                origin: config('passkey.origin', 'http://localhost:8000'),
                challengeStore: new LaravelSessionChallengeStore(),
                credentialStore: $app->make(CredentialStore::class),
                challengeTimeoutSeconds: (float) config('passkey.challenge_timeout', 300),
                allowMultipleCredentials: (bool) config('passkey.allow_multiple_credentials', false),
            );
        });

        $this->app->singleton(PasskeyHandler::class, function ($app) {
            return new PasskeyHandler($app->make(PasskeyConfig::class));
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/config/passkey.php' => config_path('passkey.php'),
        ]);

        Route::prefix(config('passkey.route_prefix', 'passkey'))
            ->middleware('web')
            ->group(function () {
                Route::post('/register/begin', [PasskeyController::class, 'beginRegistration']);
                Route::post('/register/finish', [PasskeyController::class, 'finishRegistration']);
                Route::post('/login/begin', [PasskeyController::class, 'beginAuthentication']);
                Route::post('/login/finish', [PasskeyController::class, 'finishAuthentication']);
            });
    }
}
