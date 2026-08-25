<?php

declare(strict_types=1);

namespace OpenPasskey\Symfony;

use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class PasskeyController
{
    public function __construct(
        private readonly PasskeyHandler $handler,
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

        return new JsonResponse($result);
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

        return new JsonResponse($result);
    }
}
