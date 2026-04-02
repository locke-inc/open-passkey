import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/server";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

type ActionFunctionArgs = { request: Request };
type ActionFunction = (args: ActionFunctionArgs) => Promise<Response>;

function jsonResponse(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
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

export function createPasskeyActions(config: PasskeyConfig): {
  registerBegin: ActionFunction;
  registerFinish: ActionFunction;
  loginBegin: ActionFunction;
  loginFinish: ActionFunction;
} {
  const passkey = new Passkey(config);

  return {
    registerBegin: ({ request }: ActionFunctionArgs) =>
      handle(request, (body) => passkey.beginRegistration(body as Parameters<typeof passkey.beginRegistration>[0])),

    registerFinish: ({ request }: ActionFunctionArgs) =>
      handle(request, (body) => passkey.finishRegistration(body as Parameters<typeof passkey.finishRegistration>[0])),

    loginBegin: ({ request }: ActionFunctionArgs) =>
      handle(request, (body) => passkey.beginAuthentication(body as Parameters<typeof passkey.beginAuthentication>[0])),

    loginFinish: ({ request }: ActionFunctionArgs) =>
      handle(request, (body) => passkey.finishAuthentication(body as Parameters<typeof passkey.finishAuthentication>[0])),
  };
}
