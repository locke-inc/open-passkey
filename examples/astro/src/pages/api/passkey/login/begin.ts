import type { APIRoute } from "astro";
import { endpoints } from "../../../../lib/passkey";
export const POST: APIRoute = (context) => endpoints.loginBegin(context);
