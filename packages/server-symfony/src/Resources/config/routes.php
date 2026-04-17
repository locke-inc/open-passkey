<?php

use OpenPasskey\Symfony\PasskeyController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return function (RoutingConfigurator $routes): void {
    $routes->add('passkey_register_begin', '/passkey/register/begin')
        ->controller([PasskeyController::class, 'beginRegistration'])
        ->methods(['POST']);

    $routes->add('passkey_register_finish', '/passkey/register/finish')
        ->controller([PasskeyController::class, 'finishRegistration'])
        ->methods(['POST']);

    $routes->add('passkey_login_begin', '/passkey/login/begin')
        ->controller([PasskeyController::class, 'beginAuthentication'])
        ->methods(['POST']);

    $routes->add('passkey_login_finish', '/passkey/login/finish')
        ->controller([PasskeyController::class, 'finishAuthentication'])
        ->methods(['POST']);

    $routes->add('passkey_session', '/passkey/session')
        ->controller([PasskeyController::class, 'getSession'])
        ->methods(['GET']);

    $routes->add('passkey_logout', '/passkey/logout')
        ->controller([PasskeyController::class, 'logout'])
        ->methods(['POST']);
};
