<?php

declare(strict_types=1);

namespace OpenPasskey\Server\Tests;

use OpenPasskey\Server\Session;
use OpenPasskey\Server\SessionConfig;
use OpenPasskey\Server\SessionTokenData;
use PHPUnit\Framework\TestCase;

class SessionTest extends TestCase
{
    private function config(string $secret = 'test-secret-that-is-at-least-32-chars'): SessionConfig
    {
        return new SessionConfig(secret: $secret, secure: false);
    }

    public function testCreateAndValidateToken(): void
    {
        $config = $this->config();
        $token = Session::createToken('alice@example.com', $config);

        $data = Session::validateToken($token, $config);
        $this->assertSame('alice@example.com', $data->userId);
        $this->assertGreaterThan(0, $data->expiresAt);
    }

    public function testTokenWithColonsInUserId(): void
    {
        $config = $this->config();
        $token = Session::createToken('urn:user:alice:123', $config);

        $data = Session::validateToken($token, $config);
        $this->assertSame('urn:user:alice:123', $data->userId);
    }

    public function testTamperedTokenFails(): void
    {
        $config = $this->config();
        $token = Session::createToken('alice', $config);

        $this->expectException(\ValueError::class);
        Session::validateToken('bob' . substr($token, 5), $config);
    }

    public function testExpiredTokenFails(): void
    {
        $config = new SessionConfig(
            secret: 'test-secret-that-is-at-least-32-chars',
            durationSeconds: 0,
            clockSkewGraceSeconds: 0,
        );
        $token = Session::createToken('alice', $config);

        usleep(10_000);

        $this->expectException(\ValueError::class);
        $this->expectExceptionMessage('session expired');
        Session::validateToken($token, $config);
    }

    public function testSecretTooShort(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Session::validateConfig(new SessionConfig(secret: 'short'));
    }

    public function testBuildSetCookieHeader(): void
    {
        $config = $this->config();
        $header = Session::buildSetCookieHeader('mytoken', $config);

        $this->assertStringContainsString('op_session=mytoken', $header);
        $this->assertStringContainsString('HttpOnly', $header);
        $this->assertStringContainsString('Path=/', $header);
        $this->assertStringContainsString('Max-Age=86400', $header);
        $this->assertStringContainsString('SameSite=Lax', $header);
        $this->assertStringNotContainsString('Secure', $header);
    }

    public function testBuildSetCookieHeaderSecure(): void
    {
        $config = new SessionConfig(
            secret: 'test-secret-that-is-at-least-32-chars',
            secure: true,
        );
        $header = Session::buildSetCookieHeader('mytoken', $config);
        $this->assertStringContainsString('Secure', $header);
    }

    public function testBuildClearCookieHeader(): void
    {
        $config = $this->config();
        $header = Session::buildClearCookieHeader($config);

        $this->assertStringContainsString('op_session=', $header);
        $this->assertStringContainsString('Max-Age=0', $header);
    }

    public function testParseCookieToken(): void
    {
        $config = $this->config();

        $this->assertNull(Session::parseCookieToken(null, $config));
        $this->assertNull(Session::parseCookieToken('', $config));
        $this->assertNull(Session::parseCookieToken('other=value', $config));
        $this->assertSame('abc123', Session::parseCookieToken('op_session=abc123', $config));
        $this->assertSame('abc123', Session::parseCookieToken('other=x; op_session=abc123; more=y', $config));
        $this->assertNull(Session::parseCookieToken('op_session=', $config));
    }
}
