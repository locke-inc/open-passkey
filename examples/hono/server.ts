import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { createPasskeyApp, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/hono";

const app = new Hono();

app.route("/passkey", createPasskeyApp({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Hono Example",
  origin: "http://localhost:3003",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
}));

app.use("/*", serveStatic({ root: "./public" }));
app.use("/*", serveStatic({ root: "../shared" }));

serve({ fetch: app.fetch, port: 3003 }, () => console.log("Hono example running on http://localhost:3003"));
