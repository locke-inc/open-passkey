import express from "express";
import { createPasskeyRouter, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/express";

const app = express();
app.use(express.json());
app.use("/passkey", createPasskeyRouter({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Solid Example",
  origin: "http://localhost:3011",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
}));

app.listen(3012, () => console.log("API server running on http://localhost:3012"));
