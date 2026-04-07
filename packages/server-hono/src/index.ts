import { Hono } from "hono";
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

export function createPasskeyApp(config: PasskeyConfig): Hono {
  const passkey = new Passkey(config);
  const app = new Hono();

  app.post("/register/begin", async (c) => {
    try {
      const body = await c.req.json();
      const result = await passkey.beginRegistration(body);
      return c.json(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return c.json({ error: err.message }, err.statusCode as 400);
      }
      return c.json({ error: "internal server error" }, 500);
    }
  });

  app.post("/register/finish", async (c) => {
    try {
      const body = await c.req.json();
      const result = await passkey.finishRegistration(body);
      return c.json(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return c.json({ error: err.message }, err.statusCode as 400);
      }
      return c.json({ error: "internal server error" }, 500);
    }
  });

  app.post("/login/begin", async (c) => {
    try {
      const body = await c.req.json();
      const result = await passkey.beginAuthentication(body);
      return c.json(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return c.json({ error: err.message }, err.statusCode as 400);
      }
      return c.json({ error: "internal server error" }, 500);
    }
  });

  app.post("/login/finish", async (c) => {
    try {
      const body = await c.req.json();
      const result = await passkey.finishAuthentication(body);
      const sessionConfig = passkey.getSessionConfig();
      if (sessionConfig && result.sessionToken) {
        c.header("Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
        const { sessionToken, ...rest } = result;
        return c.json(rest);
      }
      return c.json(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return c.json({ error: err.message }, err.statusCode as 400);
      }
      return c.json({ error: "internal server error" }, 500);
    }
  });

  const sessionConfig = passkey.getSessionConfig();
  if (sessionConfig) {
    app.get("/session", (c) => {
      try {
        const token = parseCookieToken(c.req.header("Cookie"), sessionConfig);
        if (!token) {
          return c.json({ error: "no session" }, 401);
        }
        const data = passkey.getSessionTokenData(token);
        return c.json({ userId: data.userId, authenticated: true });
      } catch {
        return c.json({ error: "invalid session" }, 401);
      }
    });

    app.post("/logout", (c) => {
      c.header("Set-Cookie", buildClearCookieHeader(sessionConfig));
      return c.json({ success: true });
    });
  }

  return app;
}
