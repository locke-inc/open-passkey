import { handlers } from "../../utils/passkey";

export default defineEventHandler((event) => handlers.session(event));
