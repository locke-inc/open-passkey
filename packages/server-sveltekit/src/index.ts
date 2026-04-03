import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/server";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

type RequestHandler = (event: { request: Request }) => Promise<Response>;

export interface PasskeyHandlers {
  registerBegin: RequestHandler;
  registerFinish: RequestHandler;
  loginBegin: RequestHandler;
  loginFinish: RequestHandler;
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
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

    loginFinish: ({ request }) =>
      handle(request, (body) => passkey.finishAuthentication(body as Parameters<Passkey["finishAuthentication"]>[0])),
  };
}
