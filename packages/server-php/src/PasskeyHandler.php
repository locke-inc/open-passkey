<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

use OpenPasskey\Base64Url;
use OpenPasskey\WebAuthn;
use OpenPasskey\WebAuthnException;

class PasskeyHandler
{
    public function __construct(
        private readonly PasskeyConfig $config,
    ) {}

    public function beginRegistration(string $userId, string $username): array
    {
        if ($userId === '' || $username === '') {
            throw new PasskeyError('userId and username are required');
        }

        if (!$this->config->allowMultipleCredentials) {
            $existing = $this->config->credentialStore->getByUser($userId);
            if (count($existing) > 0) {
                throw new PasskeyError('user already registered', 409);
            }
        }

        $challenge = Base64Url::encode(random_bytes($this->config->challengeLength));
        $prfSalt = Base64Url::encode(random_bytes(32));

        $challengeData = json_encode(['challenge' => $challenge, 'prfSalt' => $prfSalt]);
        $this->config->challengeStore->store($userId, $challengeData, $this->config->challengeTimeoutSeconds);

        $options = [
            'challenge' => $challenge,
            'rp' => [
                'id' => $this->config->rpId,
                'name' => $this->config->rpDisplayName,
            ],
            'user' => [
                'id' => Base64Url::encode($userId),
                'name' => $username,
                'displayName' => $username,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -52],
                ['type' => 'public-key', 'alg' => -49],
                ['type' => 'public-key', 'alg' => -7],
            ],
            'authenticatorSelection' => [
                'residentKey' => 'preferred',
                'userVerification' => 'preferred',
            ],
            'timeout' => (int) ($this->config->challengeTimeoutSeconds * 1000),
            'attestation' => 'none',
            'extensions' => [
                'prf' => [
                    'eval' => [
                        'first' => $prfSalt,
                    ],
                ],
            ],
        ];

        if ($this->config->allowMultipleCredentials) {
            $existing = $this->config->credentialStore->getByUser($userId);
            if (count($existing) > 0) {
                $options['excludeCredentials'] = array_map(
                    fn(StoredCredential $c) => [
                        'type' => 'public-key',
                        'id' => Base64Url::encode($c->credentialId),
                    ],
                    $existing,
                );
            }
        }

        return $options;
    }

    public function finishRegistration(string $userId, array $credential, bool $prfSupported = false): array
    {
        $challengeDataJson = $this->config->challengeStore->consume($userId);
        $challengeData = json_decode($challengeDataJson, true);
        $expectedChallenge = $challengeData['challenge'];
        $prfSalt = $challengeData['prfSalt'];

        if (!$this->config->allowMultipleCredentials) {
            $existing = $this->config->credentialStore->getByUser($userId);
            if (count($existing) > 0) {
                throw new PasskeyError('user already registered', 409);
            }
        }

        $response = $credential['response'] ?? [];

        try {
            $result = WebAuthn::verifyRegistration(
                rpId: $this->config->rpId,
                expectedChallenge: $expectedChallenge,
                expectedOrigin: $this->config->origin,
                clientDataJSON: $response['clientDataJSON'] ?? '',
                attestationObject: $response['attestationObject'] ?? '',
            );
        } catch (WebAuthnException $e) {
            throw new PasskeyError('registration verification failed: ' . $e->getMessage());
        }

        $storedCred = new StoredCredential(
            credentialId: Base64Url::decode($result->credentialId),
            publicKeyCose: Base64Url::decode($result->publicKeyCose),
            signCount: $result->signCount,
            userId: $userId,
            prfSalt: $prfSupported ? Base64Url::decode($prfSalt) : null,
            prfSupported: $prfSupported,
        );

        $this->config->credentialStore->store($storedCred);

        $response = [
            'credentialId' => $result->credentialId,
            'registered' => true,
            'prfSupported' => $prfSupported,
        ];

        if ($this->config->session !== null) {
            $response['sessionToken'] = Session::createToken($userId, $this->config->session);
        }

        return $response;
    }

    public function beginAuthentication(string $userId = ''): array
    {
        $challenge = Base64Url::encode(random_bytes($this->config->challengeLength));
        $challengeKey = $userId !== '' ? $userId : $challenge;
        $this->config->challengeStore->store($challengeKey, $challenge, $this->config->challengeTimeoutSeconds);

        $options = [
            'challenge' => $challenge,
            'rpId' => $this->config->rpId,
            'timeout' => (int) ($this->config->challengeTimeoutSeconds * 1000),
            'userVerification' => 'preferred',
        ];

        if ($userId !== '') {
            $creds = $this->config->credentialStore->getByUser($userId);
            $options['allowCredentials'] = array_map(
                fn(StoredCredential $c) => [
                    'type' => 'public-key',
                    'id' => Base64Url::encode($c->credentialId),
                ],
                $creds,
            );

            $prfCreds = array_filter($creds, fn(StoredCredential $c) => $c->prfSupported && $c->prfSalt !== null);
            if (count($prfCreds) > 0) {
                $evalByCredential = [];
                foreach ($prfCreds as $c) {
                    $evalByCredential[Base64Url::encode($c->credentialId)] = [
                        'first' => Base64Url::encode($c->prfSalt),
                    ];
                }
                $options['extensions'] = [
                    'prf' => [
                        'evalByCredential' => $evalByCredential,
                    ],
                ];
            }
        }

        return $options;
    }

    public function finishAuthentication(string $userId, array $credential): array
    {
        $challengeKey = $userId;
        $challenge = $this->config->challengeStore->consume($challengeKey);

        $credentialIdB64 = $credential['id'] ?? '';
        $credentialIdBytes = Base64Url::decode($credentialIdB64);

        $stored = $this->config->credentialStore->get($credentialIdBytes);

        $response = $credential['response'] ?? [];
        $userHandle = $response['userHandle'] ?? null;
        if ($userHandle !== null && $userHandle !== '') {
            $decodedHandle = Base64Url::decode($userHandle);
            if ($decodedHandle !== $stored->userId) {
                throw new PasskeyError('userHandle does not match credential owner');
            }
        }

        try {
            $result = WebAuthn::verifyAuthentication(
                rpId: $this->config->rpId,
                expectedChallenge: $challenge,
                expectedOrigin: $this->config->origin,
                storedPublicKeyCose: $stored->publicKeyCose,
                storedSignCount: $stored->signCount,
                clientDataJSON: $response['clientDataJSON'] ?? '',
                authenticatorData: $response['authenticatorData'] ?? '',
                signature: $response['signature'] ?? '',
            );
        } catch (WebAuthnException $e) {
            throw new PasskeyError('authentication verification failed: ' . $e->getMessage());
        }

        $stored->signCount = $result->signCount;
        $this->config->credentialStore->update($stored);

        $resp = [
            'userId' => $stored->userId,
            'authenticated' => true,
        ];

        if ($stored->prfSupported) {
            $resp['prfSupported'] = true;
        }

        if ($this->config->session !== null) {
            $resp['sessionToken'] = Session::createToken($stored->userId, $this->config->session);
        }

        return $resp;
    }

    public function getSessionTokenData(string $token): SessionTokenData
    {
        if ($this->config->session === null) {
            throw new PasskeyError('session is not configured', 500);
        }

        return Session::validateToken($token, $this->config->session);
    }
}
