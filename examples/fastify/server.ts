import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import path from "path";
import { fileURLToPath } from "url";
import { passkeyPlugin, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/fastify";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fastify = Fastify({ logger: true });

fastify.register(fastifyStatic, { root: path.join(__dirname, "public") });
fastify.register(fastifyStatic, { root: path.join(__dirname, "../shared"), prefix: "/", decorateReply: false });

fastify.register(async (instance) => {
  instance.register(passkeyPlugin, {
    rpId: "localhost",
    rpDisplayName: "Open Passkey Fastify Example",
    origin: "http://localhost:3002",
    challengeStore: new MemoryChallengeStore(),
    credentialStore: new MemoryCredentialStore(),
  });
}, { prefix: "/passkey" });

fastify.listen({ port: 3002 }, () => console.log("Fastify example running on http://localhost:3002"));
