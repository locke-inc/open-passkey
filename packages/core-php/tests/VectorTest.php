<?php

declare(strict_types=1);

namespace OpenPasskey\Tests;

use OpenPasskey\WebAuthn;
use OpenPasskey\WebAuthnException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class VectorTest extends TestCase
{
    private const VECTORS_DIR = __DIR__ . '/../../../spec/vectors';

    private static function loadVectors(string $filename): array
    {
        $path = self::VECTORS_DIR . '/' . $filename;
        $data = json_decode(file_get_contents($path), true);
        self::assertNotEmpty($data['vectors'], "Vector file {$filename} contains no test vectors");
        return $data['vectors'];
    }

    private static function namedVectors(string $filename): array
    {
        $vectors = self::loadVectors($filename);
        $named = [];
        foreach ($vectors as $v) {
            $named[$v['name']] = [$v];
        }
        return $named;
    }

    public static function registrationVectors(): array
    {
        return self::namedVectors('registration.json');
    }

    public static function authenticationVectors(): array
    {
        return self::namedVectors('authentication.json');
    }

    public static function hybridAuthenticationVectors(): array
    {
        return self::namedVectors('hybrid_authentication.json');
    }

    #[DataProvider('registrationVectors')]
    public function testRegistration(array $vector): void
    {
        $input = $vector['input'];
        $credential = $input['credential'];
        $response = $credential['response'];

        if ($vector['expected']['success']) {
            $result = WebAuthn::verifyRegistration(
                rpId: $input['rpId'],
                expectedChallenge: $input['expectedChallenge'],
                expectedOrigin: $input['expectedOrigin'],
                clientDataJSON: $response['clientDataJSON'],
                attestationObject: $response['attestationObject'],
            );

            $expected = $vector['expected'];
            if (isset($expected['credentialId'])) {
                $this->assertSame($expected['credentialId'], $result->credentialId);
            }
            if (isset($expected['publicKeyCose'])) {
                $this->assertSame($expected['publicKeyCose'], $result->publicKeyCose);
            }
            if (isset($expected['signCount'])) {
                $this->assertSame($expected['signCount'], $result->signCount);
            }
            if (isset($expected['rpIdHash'])) {
                $this->assertSame($expected['rpIdHash'], $result->rpIdHash);
            }
        } else {
            try {
                WebAuthn::verifyRegistration(
                    rpId: $input['rpId'],
                    expectedChallenge: $input['expectedChallenge'],
                    expectedOrigin: $input['expectedOrigin'],
                    clientDataJSON: $response['clientDataJSON'],
                    attestationObject: $response['attestationObject'],
                );
                $this->fail("Expected error '{$vector['expected']['error']}', got success");
            } catch (WebAuthnException $e) {
                $this->assertSame($vector['expected']['error'], $e->getErrorCode());
            }
        }
    }

    #[DataProvider('authenticationVectors')]
    public function testAuthentication(array $vector): void
    {
        $this->runAuthenticationVector($vector);
    }

    #[DataProvider('hybridAuthenticationVectors')]
    public function testHybridAuthentication(array $vector): void
    {
        $this->runAuthenticationVector($vector);
    }

    private function runAuthenticationVector(array $vector): void
    {
        $input = $vector['input'];
        $credential = $input['credential'];
        $response = $credential['response'];

        $storedPublicKeyCose = self::b64Decode($input['storedPublicKeyCose']);
        $storedSignCount = (int) $input['storedSignCount'];

        if ($vector['expected']['success']) {
            $result = WebAuthn::verifyAuthentication(
                rpId: $input['rpId'],
                expectedChallenge: $input['expectedChallenge'],
                expectedOrigin: $input['expectedOrigin'],
                storedPublicKeyCose: $storedPublicKeyCose,
                storedSignCount: $storedSignCount,
                clientDataJSON: $response['clientDataJSON'],
                authenticatorData: $response['authenticatorData'],
                signature: $response['signature'],
            );

            if (isset($vector['expected']['signCount'])) {
                $this->assertSame($vector['expected']['signCount'], $result->signCount);
            }
        } else {
            try {
                WebAuthn::verifyAuthentication(
                    rpId: $input['rpId'],
                    expectedChallenge: $input['expectedChallenge'],
                    expectedOrigin: $input['expectedOrigin'],
                    storedPublicKeyCose: $storedPublicKeyCose,
                    storedSignCount: $storedSignCount,
                    clientDataJSON: $response['clientDataJSON'],
                    authenticatorData: $response['authenticatorData'],
                    signature: $response['signature'],
                );
                $this->fail("Expected error '{$vector['expected']['error']}', got success");
            } catch (WebAuthnException $e) {
                $this->assertSame($vector['expected']['error'], $e->getErrorCode());
            }
        }
    }

    private static function b64Decode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'), true);
    }
}
