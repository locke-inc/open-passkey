<?php

declare(strict_types=1);

namespace OpenPasskey\Laravel;

use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use OpenPasskey\Server\CredentialStore;
use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;
use OpenPasskey\Server\SessionConfig;

class PasskeyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/config/passkey.php', 'passkey');

        $this->app->singleton(PasskeyConfig::class, function ($app) {
            if (!$app->bound(CredentialStore::class)) {
                throw new PasskeyError('CredentialStore not bound — bind your own implementation in a service provider', 500);
            }

            $sessionConfig = null;
            $sessionArr = config('passkey.session', []);
            if (!empty($sessionArr['secret'])) {
                $sessionConfig = new SessionConfig(
                    secret: $sessionArr['secret'],
                    durationSeconds: $sessionArr['duration'] ?? 86400,
                    secure: $sessionArr['secure'] ?? true,
                );
            }

            return new PasskeyConfig(
                rpId: config('passkey.rp_id', 'localhost'),
                rpDisplayName: config('passkey.rp_display_name', 'My App'),
                origin: config('passkey.origin', 'http://localhost:8000'),
                challengeStore: new LaravelSessionChallengeStore(),
                credentialStore: $app->make(CredentialStore::class),
                challengeTimeoutSeconds: (float) config('passkey.challenge_timeout', 300),
                allowMultipleCredentials: (bool) config('passkey.allow_multiple_credentials', false),
                session: $sessionConfig,
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

        $cookieName = config('passkey.session.cookie_name', 'op_session');
        $this->app->resolving(EncryptCookies::class, function (EncryptCookies $middleware) use ($cookieName) {
            $middleware->disableFor($cookieName);
        });

        Route::prefix(config('passkey.route_prefix', 'passkey'))
            ->middleware('web')
            ->group(function () {
                Route::post('/register/begin', [PasskeyController::class, 'beginRegistration']);
                Route::post('/register/finish', [PasskeyController::class, 'finishRegistration']);
                Route::post('/login/begin', [PasskeyController::class, 'beginAuthentication']);
                Route::post('/login/finish', [PasskeyController::class, 'finishAuthentication']);
                Route::get('/session', [PasskeyController::class, 'getSession']);
                Route::post('/logout', [PasskeyController::class, 'logout']);
            });
    }
}
