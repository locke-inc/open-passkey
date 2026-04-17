<?php

declare(strict_types=1);

namespace OpenPasskey\Laravel;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;
use OpenPasskey\Server\Session;

class PasskeyController extends Controller
{
    public function __construct(
        private readonly PasskeyHandler $handler,
        private readonly PasskeyConfig $config,
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

        return $this->withSessionCookie($result);
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

        return $this->withSessionCookie($result);
    }

    public function getSession(Request $request): JsonResponse
    {
        if ($this->config->session === null) {
            return response()->json(['error' => 'session is not configured'], 500);
        }

        $token = Session::parseCookieToken($request->header('Cookie'), $this->config->session);
        if ($token === null) {
            return response()->json(['error' => 'no session cookie'], 401);
        }

        try {
            $data = $this->handler->getSessionTokenData($token);
        } catch (PasskeyError|\ValueError $e) {
            return response()->json(['error' => 'invalid session'], 401);
        }

        return response()->json(['userId' => $data->userId, 'authenticated' => true]);
    }

    public function logout(): JsonResponse
    {
        if ($this->config->session === null) {
            return response()->json(['error' => 'session is not configured'], 500);
        }

        return response()->json(['success' => true])
            ->withHeaders(['Set-Cookie' => Session::buildClearCookieHeader($this->config->session)]);
    }

    private function withSessionCookie(array $result): JsonResponse
    {
        if ($this->config->session !== null && isset($result['sessionToken'])) {
            $token = $result['sessionToken'];
            unset($result['sessionToken']);
            return response()->json($result)
                ->withHeaders(['Set-Cookie' => Session::buildSetCookieHeader($token, $this->config->session)]);
        }

        return response()->json($result);
    }
}
