import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
  buildSetCookieHeader,
  buildClearCookieHeader,
  parseCookieToken,
} from "@open-passkey/server";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

type RequestHandler = (event: { request: Request }) => Promise<Response>;

export interface PasskeyHandlers {
  registerBegin: RequestHandler;
  registerFinish: RequestHandler;
  loginBegin: RequestHandler;
  loginFinish: RequestHandler;
  session: RequestHandler;
  logout: RequestHandler;
}

function jsonResponse(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

async function handle(
  request: Request,
  fn: (body: unknown) => Promise<unknown>,
): Promise<Response> {
  try {
    const body = await request.json();
    const result = await fn(body);
    return jsonResponse(result);
  } catch (err) {
    if (err instanceof PasskeyError) {
      return jsonResponse({ error: err.message }, err.statusCode);
    }
    return jsonResponse({ error: "internal server error" }, 500);
  }
}

export function createPasskeyHandlers(config: PasskeyConfig): PasskeyHandlers {
  const passkey = new Passkey(config);

  return {
    registerBegin: ({ request }) =>
      handle(request, (body) => passkey.beginRegistration(body as Parameters<Passkey["beginRegistration"]>[0])),

    registerFinish: ({ request }) =>
      handle(request, (body) => passkey.finishRegistration(body as Parameters<Passkey["finishRegistration"]>[0])),

    loginBegin: ({ request }) =>
      handle(request, (body) => passkey.beginAuthentication(body as Parameters<Passkey["beginAuthentication"]>[0])),

    loginFinish: async ({ request }) => {
      try {
        const body = await request.json();
        const result = await passkey.finishAuthentication(body as Parameters<Passkey["finishAuthentication"]>[0]);
        const sessionConfig = passkey.getSessionConfig();
        if (sessionConfig && result.sessionToken) {
          const { sessionToken: _, ...responseBody } = result;
          return jsonResponse(responseBody, 200, { "Set-Cookie": buildSetCookieHeader(result.sessionToken, sessionConfig) });
        }
        return jsonResponse(result);
      } catch (err) {
        if (err instanceof PasskeyError) {
          return jsonResponse({ error: err.message }, err.statusCode);
        }
        return jsonResponse({ error: "internal server error" }, 500);
      }
    },

    session: async ({ request }) => {
      const sessionConfig = passkey.getSessionConfig();
      if (!sessionConfig) {
        return jsonResponse({ error: "session not enabled" }, 404);
      }
      try {
        const token = parseCookieToken(request.headers.get("cookie"), sessionConfig);
        if (!token) {
          return jsonResponse({ error: "no session" }, 401);
        }
        const data = passkey.getSessionTokenData(token);
        return jsonResponse({ userId: data.userId, authenticated: true });
      } catch {
        return jsonResponse({ error: "invalid session" }, 401);
      }
    },

    logout: async () => {
      const sessionConfig = passkey.getSessionConfig();
      const headers: Record<string, string> = {};
      if (sessionConfig) {
        headers["Set-Cookie"] = buildClearCookieHeader(sessionConfig);
      }
      return jsonResponse({ success: true }, 200, headers);
    },
  };
}
