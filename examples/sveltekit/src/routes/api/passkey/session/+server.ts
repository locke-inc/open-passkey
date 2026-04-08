import { handlers } from "$lib/server/passkey";
import type { RequestHandler } from "./$types";

export const GET: RequestHandler = (event) => handlers.session(event);
