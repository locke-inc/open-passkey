import { Router } from "express";
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
import type { Request, Response } from "express";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

async function handle(res: Response, fn: () => Promise<unknown>): Promise<void> {
  try {
    const result = await fn();
    res.json(result);
  } catch (err) {
    if (err instanceof PasskeyError) {
      res.status(err.statusCode).json({ error: err.message });
    } else {
      res.status(500).json({ error: "internal server error" });
    }
  }
}

export function createPasskeyRouter(config: PasskeyConfig): Router {
  const passkey = new Passkey(config);
  const router = Router();

  router.post("/register/begin", (req: Request, res: Response) => {
    handle(res, () => passkey.beginRegistration(req.body));
  });

  router.post("/register/finish", (req: Request, res: Response) => {
    handle(res, () => passkey.finishRegistration(req.body));
  });

  router.post("/login/begin", (req: Request, res: Response) => {
    handle(res, () => passkey.beginAuthentication(req.body));
  });

  router.post("/login/finish", async (req: Request, res: Response) => {
    try {
      const result = await passkey.finishAuthentication(req.body);
      const sessionConfig = passkey.getSessionConfig();
      if (sessionConfig && result.sessionToken) {
        res.setHeader("Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
        const { sessionToken: _, ...body } = result;
        res.json(body);
      } else {
        res.json(result);
      }
    } catch (err) {
      if (err instanceof PasskeyError) {
        res.status(err.statusCode).json({ error: err.message });
      } else {
        res.status(500).json({ error: "internal server error" });
      }
    }
  });

  const sessionConfig = passkey.getSessionConfig();
  if (sessionConfig) {
    router.get("/session", (req: Request, res: Response) => {
      try {
        const token = parseCookieToken(req.headers.cookie, sessionConfig);
        if (!token) {
          res.status(401).json({ error: "no session" });
          return;
        }
        const data = passkey.getSessionTokenData(token);
        res.json({ userId: data.userId, authenticated: true });
      } catch {
        res.status(401).json({ error: "invalid session" });
      }
    });

    router.post("/logout", (_req: Request, res: Response) => {
      res.setHeader("Set-Cookie", buildClearCookieHeader(sessionConfig));
      res.json({ success: true });
    });
  }

  return router;
}
