import { Router } from "express";
import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
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

  router.post("/login/finish", (req: Request, res: Response) => {
    handle(res, () => passkey.finishAuthentication(req.body));
  });

  return router;
}
