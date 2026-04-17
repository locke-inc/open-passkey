<?php

declare(strict_types=1);

namespace OpenPasskey\Symfony;

use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;
use OpenPasskey\Server\Session;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class PasskeyController
{
    public function __construct(
        private readonly PasskeyHandler $handler,
        private readonly PasskeyConfig $config,
    ) {}

    public function beginRegistration(Request $request): JsonResponse
    {
        $body = json_decode($request->getContent(), true) ?? [];
        try {
            return new JsonResponse($this->handler->beginRegistration(
                $body['userId'] ?? '',
                $body['username'] ?? '',
            ));
        } catch (PasskeyError $e) {
            return new JsonResponse(['error' => $e->getMessage()], $e->statusCode);
        }
    }

    public function finishRegistration(Request $request): JsonResponse
    {
        $body = json_decode($request->getContent(), true) ?? [];
        try {
            $result = $this->handler->finishRegistration(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
                $body['prfSupported'] ?? false,
            );
        } catch (PasskeyError $e) {
            return new JsonResponse(['error' => $e->getMessage()], $e->statusCode);
        }

        return $this->withSessionCookie($result);
    }

    public function beginAuthentication(Request $request): JsonResponse
    {
        $body = json_decode($request->getContent(), true) ?? [];
        try {
            return new JsonResponse($this->handler->beginAuthentication($body['userId'] ?? ''));
        } catch (PasskeyError $e) {
            return new JsonResponse(['error' => $e->getMessage()], $e->statusCode);
        }
    }

    public function finishAuthentication(Request $request): JsonResponse
    {
        $body = json_decode($request->getContent(), true) ?? [];
        try {
            $result = $this->handler->finishAuthentication(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
            );
        } catch (PasskeyError $e) {
            return new JsonResponse(['error' => $e->getMessage()], $e->statusCode);
        }

        return $this->withSessionCookie($result);
    }

    public function getSession(Request $request): JsonResponse
    {
        if ($this->config->session === null) {
            return new JsonResponse(['error' => 'session is not configured'], 500);
        }

        $token = Session::parseCookieToken($request->headers->get('Cookie'), $this->config->session);
        if ($token === null) {
            return new JsonResponse(['error' => 'no session cookie'], 401);
        }

        try {
            $data = $this->handler->getSessionTokenData($token);
        } catch (PasskeyError|\ValueError $e) {
            return new JsonResponse(['error' => 'invalid session'], 401);
        }

        return new JsonResponse(['userId' => $data->userId, 'authenticated' => true]);
    }

    public function logout(): JsonResponse
    {
        if ($this->config->session === null) {
            return new JsonResponse(['error' => 'session is not configured'], 500);
        }

        $response = new JsonResponse(['success' => true]);
        $response->headers->set('Set-Cookie', Session::buildClearCookieHeader($this->config->session));
        return $response;
    }

    private function withSessionCookie(array $result): JsonResponse
    {
        if ($this->config->session !== null && isset($result['sessionToken'])) {
            $token = $result['sessionToken'];
            unset($result['sessionToken']);
            $response = new JsonResponse($result);
            $response->headers->set('Set-Cookie', Session::buildSetCookieHeader($token, $this->config->session));
            return $response;
        }

        return new JsonResponse($result);
    }
}
