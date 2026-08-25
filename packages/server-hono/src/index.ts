import { Hono } from "hono";
import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
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
      return c.json(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return c.json({ error: err.message }, err.statusCode as 400);
      }
      return c.json({ error: "internal server error" }, 500);
    }
  });

  return app;
}
