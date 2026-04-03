import { handlers } from "~/server/utils/passkey";
export default defineEventHandler((event) => handlers.loginFinish(event));
