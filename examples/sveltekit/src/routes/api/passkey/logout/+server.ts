import { handlers } from "$lib/server/passkey";
import type { RequestHandler } from "./$types";

export const POST: RequestHandler = (event) => handlers.logout(event);
