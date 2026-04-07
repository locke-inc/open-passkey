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

type APIContext = { request: Request };
type APIRoute = (context: APIContext) => Promise<Response>;

function jsonResponse(data: unknown, status: number, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

async function handle(request: Request, fn: (body: unknown) => Promise<unknown>): Promise<Response> {
  try {
    const body = await request.json();
    const result = await fn(body);
    return jsonResponse(result, 200);
  } catch (err) {
    if (err instanceof PasskeyError) {
      return jsonResponse({ error: err.message }, err.statusCode);
    }
    return jsonResponse({ error: "internal server error" }, 500);
  }
}

export function createPasskeyEndpoints(config: PasskeyConfig): {
  registerBegin: APIRoute;
  registerFinish: APIRoute;
  loginBegin: APIRoute;
  loginFinish: APIRoute;
  session: APIRoute;
  logout: APIRoute;
} {
  const passkey = new Passkey(config);

  return {
    registerBegin: ({ request }: APIContext) =>
      handle(request, (body) => passkey.beginRegistration(body as Parameters<typeof passkey.beginRegistration>[0])),

    registerFinish: ({ request }: APIContext) =>
      handle(request, (body) => passkey.finishRegistration(body as Parameters<typeof passkey.finishRegistration>[0])),

    loginBegin: ({ request }: APIContext) =>
      handle(request, (body) => passkey.beginAuthentication(body as Parameters<typeof passkey.beginAuthentication>[0])),

    loginFinish: async ({ request }: APIContext) => {
      try {
        const body = await request.json();
        const result = await passkey.finishAuthentication(body as Parameters<typeof passkey.finishAuthentication>[0]);
        const sessionConfig = passkey.getSessionConfig();
        if (sessionConfig && result.sessionToken) {
          const { sessionToken: _, ...responseBody } = result;
          return jsonResponse(responseBody, 200, { "Set-Cookie": buildSetCookieHeader(result.sessionToken, sessionConfig) });
        }
        return jsonResponse(result, 200);
      } catch (err) {
        if (err instanceof PasskeyError) {
          return jsonResponse({ error: err.message }, err.statusCode);
        }
        return jsonResponse({ error: "internal server error" }, 500);
      }
    },

    session: async ({ request }: APIContext) => {
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
        return jsonResponse({ userId: data.userId, authenticated: true }, 200);
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
