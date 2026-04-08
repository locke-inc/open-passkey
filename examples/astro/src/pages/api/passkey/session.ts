import type { APIRoute } from "astro";
import { endpoints } from "../../../lib/passkey";

export const GET: APIRoute = (context) => endpoints.session(context);
