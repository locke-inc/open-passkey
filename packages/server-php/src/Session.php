<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

use OpenPasskey\Base64Url;

class Session
{
    private const MIN_SECRET_LENGTH = 32;

    public static function validateConfig(SessionConfig $config): void
    {
        if (strlen($config->secret) < self::MIN_SECRET_LENGTH) {
            throw new \InvalidArgumentException(
                'session secret must be at least ' . self::MIN_SECRET_LENGTH . ' characters',
            );
        }
    }

    public static function createToken(string $userId, SessionConfig $config): string
    {
        $expiresAt = (int) (microtime(true) * 1000) + ($config->durationSeconds * 1000);
        $payload = "{$userId}:{$expiresAt}";
        $signature = hash_hmac('sha256', $payload, $config->secret, true);
        $signatureB64 = Base64Url::encode($signature);
        return "{$payload}:{$signatureB64}";
    }

    public static function validateToken(string $token, SessionConfig $config): SessionTokenData
    {
        $lastColon = strrpos($token, ':');
        if ($lastColon === false) {
            throw new \ValueError('invalid session token');
        }

        $signatureB64 = substr($token, $lastColon + 1);
        $rest = substr($token, 0, $lastColon);

        $secondLastColon = strrpos($rest, ':');
        if ($secondLastColon === false) {
            throw new \ValueError('invalid session token');
        }

        $userId = substr($rest, 0, $secondLastColon);
        $expiresAtStr = substr($rest, $secondLastColon + 1);

        if (!ctype_digit($expiresAtStr)) {
            throw new \ValueError('invalid session token');
        }

        $expiresAt = (int) $expiresAtStr;
        $payload = "{$userId}:{$expiresAtStr}";

        $expectedSig = hash_hmac('sha256', $payload, $config->secret, true);
        $providedSig = Base64Url::decode($signatureB64);

        if (!hash_equals($expectedSig, $providedSig)) {
            throw new \ValueError('invalid session token');
        }

        $nowMs = (int) (microtime(true) * 1000);
        $graceMs = $config->clockSkewGraceSeconds * 1000;
        if ($nowMs > $expiresAt + $graceMs) {
            throw new \ValueError('session expired');
        }

        return new SessionTokenData($userId, $expiresAt);
    }

    public static function buildSetCookieHeader(string $token, SessionConfig $config): string
    {
        $parts = [
            "{$config->cookieName}={$token}",
            'HttpOnly',
            "Path={$config->cookiePath}",
            "Max-Age={$config->durationSeconds}",
            "SameSite={$config->sameSite}",
        ];

        if ($config->secure) {
            $parts[] = 'Secure';
        }

        if ($config->domain !== null) {
            $parts[] = "Domain={$config->domain}";
        }

        return implode('; ', $parts);
    }

    public static function buildClearCookieHeader(SessionConfig $config): string
    {
        $parts = [
            "{$config->cookieName}=",
            'HttpOnly',
            "Path={$config->cookiePath}",
            'Max-Age=0',
            "SameSite={$config->sameSite}",
        ];

        if ($config->secure) {
            $parts[] = 'Secure';
        }

        if ($config->domain !== null) {
            $parts[] = "Domain={$config->domain}";
        }

        return implode('; ', $parts);
    }

    public static function parseCookieToken(?string $cookieHeader, SessionConfig $config): ?string
    {
        if ($cookieHeader === null || $cookieHeader === '') {
            return null;
        }

        foreach (explode(';', $cookieHeader) as $cookie) {
            $cookie = trim($cookie);
            $prefix = $config->cookieName . '=';
            if (str_starts_with($cookie, $prefix)) {
                $value = substr($cookie, strlen($prefix));
                return $value === '' ? null : $value;
            }
        }

        return null;
    }
}
