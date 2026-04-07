import { spawn, execSync, type ChildProcess } from "child_process";
import { resolve } from "path";

const EXAMPLE_DIR = resolve(import.meta.dirname, "../../../examples/nethttp");
const PORT = 4002;
const ORIGIN = `http://localhost:${PORT}`;

export interface ServerHandle {
  baseUrl: string;
  origin: string;
  cleanup: () => Promise<void>;
}

export async function startGo(): Promise<ServerHandle> {
  // Build first so startup is fast
  execSync("go build -o nethttp-e2e .", { cwd: EXAMPLE_DIR, stdio: "pipe" });

  const proc: ChildProcess = spawn("./nethttp-e2e", [], {
    cwd: EXAMPLE_DIR,
    stdio: "pipe",
  });

  await waitForServer(`${ORIGIN}/passkey/register/begin`, proc);

  return {
    baseUrl: ORIGIN,
    origin: ORIGIN,
    cleanup: async () => {
      proc.kill("SIGTERM");
      await new Promise<void>((resolve) => {
        proc.on("close", () => resolve());
        setTimeout(resolve, 2000);
      });
      // Clean up binary
      try {
        execSync("rm -f nethttp-e2e", { cwd: EXAMPLE_DIR, stdio: "pipe" });
      } catch { /* ignore */ }
    },
  };
}

async function waitForServer(url: string, proc: ChildProcess, timeoutMs = 15_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      if (res.status > 0) return;
    } catch {
      // Server not ready yet
    }
    if (proc.exitCode !== null) {
      throw new Error(`Server process exited with code ${proc.exitCode}`);
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`Server did not start within ${timeoutMs}ms`);
}
