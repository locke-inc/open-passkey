<?php

declare(strict_types=1);

namespace OpenPasskey\Laravel;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;

class PasskeyController extends Controller
{
    public function __construct(
        private readonly PasskeyHandler $handler,
    ) {}

    public function beginRegistration(Request $request): JsonResponse
    {
        $body = $request->json()->all();
        try {
            return response()->json($this->handler->beginRegistration(
                $body['userId'] ?? '',
                $body['username'] ?? '',
            ));
        } catch (PasskeyError $e) {
            return response()->json(['error' => $e->getMessage()], $e->statusCode);
        }
    }

    public function finishRegistration(Request $request): JsonResponse
    {
        $body = $request->json()->all();
        try {
            $result = $this->handler->finishRegistration(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
                $body['prfSupported'] ?? false,
            );
        } catch (PasskeyError $e) {
            return response()->json(['error' => $e->getMessage()], $e->statusCode);
        }

        return response()->json($result);
    }

    public function beginAuthentication(Request $request): JsonResponse
    {
        $body = $request->json()->all();
        try {
            return response()->json($this->handler->beginAuthentication($body['userId'] ?? ''));
        } catch (PasskeyError $e) {
            return response()->json(['error' => $e->getMessage()], $e->statusCode);
        }
    }

    public function finishAuthentication(Request $request): JsonResponse
    {
        $body = $request->json()->all();
        try {
            $result = $this->handler->finishAuthentication(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
            );
        } catch (PasskeyError $e) {
            return response()->json(['error' => $e->getMessage()], $e->statusCode);
        }

        return response()->json($result);
    }
}
