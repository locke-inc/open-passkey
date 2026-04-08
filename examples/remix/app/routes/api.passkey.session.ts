import type { LoaderFunctionArgs } from "@remix-run/node";
import { actions } from "../lib/passkey.server";

export async function loader({ request }: LoaderFunctionArgs) {
  return actions.session({ request });
}
