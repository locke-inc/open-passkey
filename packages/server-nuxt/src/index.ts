import { type H3Event, readBody, setResponseStatus, setResponseHeader, getRequestHeader } from "h3";
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

type NitroEventHandler = (event: H3Event) => Promise<unknown>;

export interface PasskeyHandlers {
  registerBegin: NitroEventHandler;
  registerFinish: NitroEventHandler;
  loginBegin: NitroEventHandler;
  loginFinish: NitroEventHandler;
  session: NitroEventHandler;
  logout: NitroEventHandler;
}

async function handle(
  event: H3Event,
  fn: (body: unknown) => Promise<unknown>,
): Promise<unknown> {
  try {
    const body = await readBody(event);
    return await fn(body);
  } catch (err) {
    if (err instanceof PasskeyError) {
      setResponseStatus(event, err.statusCode);
      return { error: err.message };
    }
    setResponseStatus(event, 500);
    return { error: "internal server error" };
  }
}

export function createPasskeyHandlers(config: PasskeyConfig): PasskeyHandlers {
  const passkey = new Passkey(config);

  return {
    registerBegin: (event: H3Event) =>
      handle(event, (body) => passkey.beginRegistration(body as Parameters<Passkey["beginRegistration"]>[0])),

    registerFinish: async (event: H3Event) => {
      try {
        const body = await readBody(event);
        const result = await passkey.finishRegistration(body as Parameters<Passkey["finishRegistration"]>[0]);
        const sessionConfig = passkey.getSessionConfig();
        if (sessionConfig && result.sessionToken) {
          setResponseHeader(event, "Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
          const { sessionToken: _, ...responseBody } = result;
          return responseBody;
        }
        return result;
      } catch (err) {
        if (err instanceof PasskeyError) {
          setResponseStatus(event, err.statusCode);
          return { error: err.message };
        }
        setResponseStatus(event, 500);
        return { error: "internal server error" };
      }
    },

    loginBegin: (event: H3Event) =>
      handle(event, (body) => passkey.beginAuthentication(body as Parameters<Passkey["beginAuthentication"]>[0])),

    loginFinish: async (event: H3Event) => {
      try {
        const body = await readBody(event);
        const result = await passkey.finishAuthentication(body as Parameters<Passkey["finishAuthentication"]>[0]);
        const sessionConfig = passkey.getSessionConfig();
        if (sessionConfig && result.sessionToken) {
          setResponseHeader(event, "Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
          const { sessionToken: _, ...responseBody } = result;
          return responseBody;
        }
        return result;
      } catch (err) {
        if (err instanceof PasskeyError) {
          setResponseStatus(event, err.statusCode);
          return { error: err.message };
        }
        setResponseStatus(event, 500);
        return { error: "internal server error" };
      }
    },

    session: async (event: H3Event) => {
      const sessionConfig = passkey.getSessionConfig();
      if (!sessionConfig) {
        setResponseStatus(event, 404);
        return { error: "session not enabled" };
      }
      try {
        const token = parseCookieToken(getRequestHeader(event, "cookie"), sessionConfig);
        if (!token) {
          setResponseStatus(event, 401);
          return { error: "no session" };
        }
        const data = passkey.getSessionTokenData(token);
        return { userId: data.userId, authenticated: true };
      } catch {
        setResponseStatus(event, 401);
        return { error: "invalid session" };
      }
    },

    logout: async (event: H3Event) => {
      const sessionConfig = passkey.getSessionConfig();
      if (sessionConfig) {
        setResponseHeader(event, "Set-Cookie", buildClearCookieHeader(sessionConfig));
      }
      return { success: true };
    },
  };
}
