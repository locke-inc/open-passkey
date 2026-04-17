<?php

return [
    'rp_id' => env('PASSKEY_RP_ID', 'localhost'),
    'rp_display_name' => env('PASSKEY_RP_DISPLAY_NAME', 'My App'),
    'origin' => env('PASSKEY_ORIGIN', 'http://localhost:8000'),
    'route_prefix' => 'passkey',
    'challenge_timeout' => 300,
    'allow_multiple_credentials' => false,
    'session' => [
        'secret' => env('PASSKEY_SESSION_SECRET'),
        'duration' => 86400,
        'secure' => env('PASSKEY_SESSION_SECURE', true),
    ],
];
