import { NextRequest, NextResponse } from "next/server";
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

type NextRouteHandler = (request: NextRequest) => Promise<NextResponse>;

export interface PasskeyHandlers {
  registerBegin: NextRouteHandler;
  registerFinish: NextRouteHandler;
  loginBegin: NextRouteHandler;
  loginFinish: NextRouteHandler;
  session: NextRouteHandler;
  logout: NextRouteHandler;
}

async function handle(
  request: NextRequest,
  fn: (body: unknown) => Promise<unknown>,
): Promise<NextResponse> {
  try {
    const body = await request.json();
    const result = await fn(body);
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof PasskeyError) {
      return NextResponse.json({ error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ error: "internal server error" }, { status: 500 });
  }
}

export function createPasskeyHandlers(config: PasskeyConfig): PasskeyHandlers {
  const passkey = new Passkey(config);

  return {
    registerBegin: (request: NextRequest) =>
      handle(request, (body) => passkey.beginRegistration(body as Parameters<Passkey["beginRegistration"]>[0])),

    registerFinish: async (request: NextRequest) => {
      try {
        const body = await request.json();
        const result = await passkey.finishRegistration(body as Parameters<Passkey["finishRegistration"]>[0]);
        const sessionConfig = passkey.getSessionConfig();
        if (sessionConfig && result.sessionToken) {
          const { sessionToken: _, ...responseBody } = result;
          const response = NextResponse.json(responseBody);
          response.headers.set("Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
          return response;
        }
        return NextResponse.json(result);
      } catch (err) {
        if (err instanceof PasskeyError) {
          return NextResponse.json({ error: err.message }, { status: err.statusCode });
        }
        return NextResponse.json({ error: "internal server error" }, { status: 500 });
      }
    },

    loginBegin: (request: NextRequest) =>
      handle(request, (body) => passkey.beginAuthentication(body as Parameters<Passkey["beginAuthentication"]>[0])),

    loginFinish: async (request: NextRequest) => {
      try {
        const body = await request.json();
        const result = await passkey.finishAuthentication(body as Parameters<Passkey["finishAuthentication"]>[0]);
        const sessionConfig = passkey.getSessionConfig();
        if (sessionConfig && result.sessionToken) {
          const { sessionToken: _, ...responseBody } = result;
          const response = NextResponse.json(responseBody);
          response.headers.set("Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
          return response;
        }
        return NextResponse.json(result);
      } catch (err) {
        if (err instanceof PasskeyError) {
          return NextResponse.json({ error: err.message }, { status: err.statusCode });
        }
        return NextResponse.json({ error: "internal server error" }, { status: 500 });
      }
    },

    session: async (request: NextRequest) => {
      const sessionConfig = passkey.getSessionConfig();
      if (!sessionConfig) {
        return NextResponse.json({ error: "session not enabled" }, { status: 404 });
      }
      try {
        const token = parseCookieToken(request.headers.get("cookie"), sessionConfig);
        if (!token) {
          return NextResponse.json({ error: "no session" }, { status: 401 });
        }
        const data = passkey.getSessionTokenData(token);
        return NextResponse.json({ userId: data.userId, authenticated: true });
      } catch {
        return NextResponse.json({ error: "invalid session" }, { status: 401 });
      }
    },

    logout: async () => {
      const sessionConfig = passkey.getSessionConfig();
      const response = NextResponse.json({ success: true });
      if (sessionConfig) {
        response.headers.set("Set-Cookie", buildClearCookieHeader(sessionConfig));
      }
      return response;
    },
  };
}
