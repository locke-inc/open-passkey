import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createPasskeyRouter, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/express";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "../shared")));
app.use(express.static(path.join(__dirname, "public")));
app.use("/passkey", createPasskeyRouter({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Express Example",
  origin: "http://localhost:3001",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
}));

app.listen(3001, () => console.log("Express example running on http://localhost:3001"));
