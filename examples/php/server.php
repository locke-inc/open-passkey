<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyHandler;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\ChallengeStore;
use OpenPasskey\Server\CredentialStore;
use OpenPasskey\Server\StoredCredential;
use OpenPasskey\Server\Session;
use OpenPasskey\Server\SessionConfig;

// PHP's built-in server re-executes this script per request, so in-memory
// stores lose state. These thin wrappers use $_SESSION and a /tmp JSON file.

class SessionChallengeStore implements ChallengeStore
{
    public function store(string $key, string $challenge, float $timeoutSeconds): void
    {
        $_SESSION['challenges'][$key] = [
            'challenge' => $challenge,
            'expiresAt' => microtime(true) + $timeoutSeconds,
        ];
    }

    public function consume(string $key): string
    {
        $entry = $_SESSION['challenges'][$key] ?? null;
        unset($_SESSION['challenges'][$key]);

        if ($entry === null || microtime(true) > $entry['expiresAt']) {
            throw new PasskeyError('challenge not found or expired');
        }

        return $entry['challenge'];
    }
}

class TmpCredentialStore implements CredentialStore
{
    private const FILE = '/tmp/open-passkey-php-example-creds.json';

    public function store(StoredCredential $cred): void
    {
        $all = $this->load();
        $all[] = $this->serialize($cred);
        $this->save($all);
    }

    public function get(string $credentialId): StoredCredential
    {
        foreach ($this->load() as $row) {
            if ($row['credentialId'] === base64_encode($credentialId)) {
                return $this->deserialize($row);
            }
        }
        throw new PasskeyError('credential not found');
    }

    public function getByUser(string $userId): array
    {
        return array_values(array_map(
            fn($row) => $this->deserialize($row),
            array_filter($this->load(), fn($row) => $row['userId'] === $userId),
        ));
    }

    public function update(StoredCredential $cred): void
    {
        $all = $this->load();
        $key = base64_encode($cred->credentialId);
        foreach ($all as $i => $row) {
            if ($row['credentialId'] === $key) {
                $all[$i] = $this->serialize($cred);
                $this->save($all);
                return;
            }
        }
        throw new PasskeyError('credential not found');
    }

    public function delete(string $credentialId): void
    {
        $all = $this->load();
        $key = base64_encode($credentialId);
        foreach ($all as $i => $row) {
            if ($row['credentialId'] === $key) {
                array_splice($all, $i, 1);
                $this->save($all);
                return;
            }
        }
        throw new PasskeyError('credential not found');
    }

    private function serialize(StoredCredential $c): array
    {
        return [
            'credentialId' => base64_encode($c->credentialId),
            'publicKeyCose' => base64_encode($c->publicKeyCose),
            'signCount' => $c->signCount,
            'userId' => $c->userId,
            'prfSalt' => $c->prfSalt !== null ? base64_encode($c->prfSalt) : null,
            'prfSupported' => $c->prfSupported,
        ];
    }

    private function deserialize(array $row): StoredCredential
    {
        return new StoredCredential(
            credentialId: base64_decode($row['credentialId']),
            publicKeyCose: base64_decode($row['publicKeyCose']),
            signCount: $row['signCount'],
            userId: $row['userId'],
            prfSalt: $row['prfSalt'] !== null ? base64_decode($row['prfSalt']) : null,
            prfSupported: $row['prfSupported'],
        );
    }

    private function load(): array
    {
        if (!file_exists(self::FILE)) {
            return [];
        }
        return json_decode(file_get_contents(self::FILE), true) ?? [];
    }

    private function save(array $data): void
    {
        file_put_contents(self::FILE, json_encode($data), LOCK_EX);
    }
}

session_start();

$config = new PasskeyConfig(
    rpId: 'localhost',
    rpDisplayName: 'Open Passkey PHP Example',
    origin: 'http://localhost:6001',
    challengeStore: new SessionChallengeStore(),
    credentialStore: new TmpCredentialStore(),
    session: new SessionConfig(
        secret: 'php-example-secret-must-be-32-charss!',
        secure: false,
    ),
);

$handler = new PasskeyHandler($config);

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET' && $uri === '/') {
    header('Content-Type: text/html');
    readfile(__DIR__ . '/public/index.html');
    exit;
}

if ($method === 'GET' && $uri === '/passkey.js') {
    header('Content-Type: application/javascript');
    readfile(__DIR__ . '/../shared/passkey.js');
    exit;
}

if ($method === 'GET' && $uri === '/style.css') {
    header('Content-Type: text/css');
    readfile(__DIR__ . '/../shared/style.css');
    exit;
}

header('Content-Type: application/json');

function jsonBody(): array
{
    return json_decode(file_get_contents('php://input'), true) ?? [];
}

function jsonResponse(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data);
}

try {
    match (true) {
        $method === 'POST' && $uri === '/passkey/register/begin' => (function () use ($handler) {
            $body = jsonBody();
            jsonResponse($handler->beginRegistration(
                $body['userId'] ?? '',
                $body['username'] ?? '',
            ));
        })(),

        $method === 'POST' && $uri === '/passkey/register/finish' => (function () use ($handler, $config) {
            $body = jsonBody();
            $result = $handler->finishRegistration(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
                $body['prfSupported'] ?? false,
            );

            if ($config->session !== null && isset($result['sessionToken'])) {
                $token = $result['sessionToken'];
                unset($result['sessionToken']);
                header('Set-Cookie: ' . Session::buildSetCookieHeader($token, $config->session));
            }

            jsonResponse($result);
        })(),

        $method === 'POST' && $uri === '/passkey/login/begin' => (function () use ($handler) {
            $body = jsonBody();
            jsonResponse($handler->beginAuthentication($body['userId'] ?? ''));
        })(),

        $method === 'POST' && $uri === '/passkey/login/finish' => (function () use ($handler, $config) {
            $body = jsonBody();
            $result = $handler->finishAuthentication(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
            );

            if ($config->session !== null && isset($result['sessionToken'])) {
                $token = $result['sessionToken'];
                unset($result['sessionToken']);
                header('Set-Cookie: ' . Session::buildSetCookieHeader($token, $config->session));
            }

            jsonResponse($result);
        })(),

        $method === 'GET' && $uri === '/passkey/session' => (function () use ($handler, $config) {
            $cookieHeader = $_SERVER['HTTP_COOKIE'] ?? null;
            $token = Session::parseCookieToken($cookieHeader, $config->session);
            if ($token === null) {
                jsonResponse(['error' => 'no session cookie'], 401);
                return;
            }
            try {
                $data = $handler->getSessionTokenData($token);
            } catch (PasskeyError|\ValueError $e) {
                jsonResponse(['error' => 'invalid session'], 401);
                return;
            }
            jsonResponse(['userId' => $data->userId, 'authenticated' => true]);
        })(),

        $method === 'POST' && $uri === '/passkey/logout' => (function () use ($config) {
            header('Set-Cookie: ' . Session::buildClearCookieHeader($config->session));
            jsonResponse(['success' => true]);
        })(),

        default => jsonResponse(['error' => 'not found'], 404),
    };
} catch (PasskeyError $e) {
    jsonResponse(['error' => $e->getMessage()], $e->statusCode);
}
