<?php

use Illuminate\Support\Facades\Route;

$sharedDir = realpath(__DIR__ . '/../../shared');

Route::get('/', function () {
    return response()->file(public_path('index.html'));
});

Route::get('/passkey.js', function () use ($sharedDir) {
    return response()->file($sharedDir . '/passkey.js', ['Content-Type' => 'application/javascript']);
});

Route::get('/style.css', function () use ($sharedDir) {
    return response()->file($sharedDir . '/style.css', ['Content-Type' => 'text/css']);
});
