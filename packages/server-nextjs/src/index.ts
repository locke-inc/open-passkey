import { NextRequest, NextResponse } from "next/server";
import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/server";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

type NextRouteHandler = (request: NextRequest) => Promise<NextResponse>;

export interface PasskeyHandlers {
  registerBegin: NextRouteHandler;
  registerFinish: NextRouteHandler;
  loginBegin: NextRouteHandler;
  loginFinish: NextRouteHandler;
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

    registerFinish: (request: NextRequest) =>
      handle(request, (body) => passkey.finishRegistration(body as Parameters<Passkey["finishRegistration"]>[0])),

    loginBegin: (request: NextRequest) =>
      handle(request, (body) => passkey.beginAuthentication(body as Parameters<Passkey["beginAuthentication"]>[0])),

    loginFinish: (request: NextRequest) =>
      handle(request, (body) => passkey.finishAuthentication(body as Parameters<Passkey["finishAuthentication"]>[0])),
  };
}
