import { type H3Event, readBody, createError } from "h3";
import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/server";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

type NitroEventHandler = (event: H3Event) => Promise<unknown>;

export interface PasskeyHandlers {
  registerBegin: NitroEventHandler;
  registerFinish: NitroEventHandler;
  loginBegin: NitroEventHandler;
  loginFinish: NitroEventHandler;
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
      throw createError({ statusCode: err.statusCode, statusMessage: err.message });
    }
    throw createError({ statusCode: 500, statusMessage: "internal server error" });
  }
}

export function createPasskeyHandlers(config: PasskeyConfig): PasskeyHandlers {
  const passkey = new Passkey(config);

  return {
    registerBegin: (event: H3Event) =>
      handle(event, (body) => passkey.beginRegistration(body as Parameters<Passkey["beginRegistration"]>[0])),

    registerFinish: (event: H3Event) =>
      handle(event, (body) => passkey.finishRegistration(body as Parameters<Passkey["finishRegistration"]>[0])),

    loginBegin: (event: H3Event) =>
      handle(event, (body) => passkey.beginAuthentication(body as Parameters<Passkey["beginAuthentication"]>[0])),

    loginFinish: (event: H3Event) =>
      handle(event, (body) => passkey.finishAuthentication(body as Parameters<Passkey["finishAuthentication"]>[0])),
  };
}
