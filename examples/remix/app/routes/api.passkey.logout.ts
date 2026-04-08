import type { ActionFunctionArgs } from "@remix-run/node";
import { actions } from "../lib/passkey.server";

export async function action({ request }: ActionFunctionArgs) {
  return actions.logout();
}
