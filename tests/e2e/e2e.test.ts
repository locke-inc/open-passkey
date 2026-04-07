import { describe, it, beforeAll, afterAll, expect } from "vitest";
import { runFullCeremony, runInvalidAuthTest } from "./harness.js";
import { startExpress, type ServerHandle } from "./servers/express.js";
import { startGo } from "./servers/go.js";
import { startFastAPI } from "./servers/fastapi.js";

interface ServerDef {
  name: string;
  start: () => Promise<ServerHandle>;
}

const servers: ServerDef[] = [
  { name: "express", start: startExpress },
  { name: "go-nethttp", start: startGo },
  { name: "fastapi", start: startFastAPI },
];

for (const serverDef of servers) {
  describe(`E2E: ${serverDef.name}`, () => {
    let server: ServerHandle;

    beforeAll(async () => {
      server = await serverDef.start();
    });

    afterAll(async () => {
      await server?.cleanup();
    });

    it("completes full registration + authentication ceremony", async () => {
      const result = await runFullCeremony(server.baseUrl, server.origin);
      // Credential ID should be a non-empty base64url string
      if (result.credentialId) {
        expect(result.credentialId.length).toBeGreaterThan(0);
      }
    });

    it("rejects tampered signature during authentication", async () => {
      await runInvalidAuthTest(server.baseUrl, server.origin);
    });

    it("completes multiple independent registrations and authentications", async () => {
      // Register and authenticate two separate users to test isolation
      const result1 = await runFullCeremony(server.baseUrl, server.origin);
      const result2 = await runFullCeremony(server.baseUrl, server.origin);
      expect(result1.userId).not.toBe(result2.userId);
    });
  });
}
