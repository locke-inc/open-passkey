import type { ActionFunctionArgs } from "@remix-run/node";
import { actions } from "~/lib/passkey.server";
export const action = ({ request }: ActionFunctionArgs) => actions.loginBegin({ request });
