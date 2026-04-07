import { spawn, type ChildProcess } from "child_process";
import { resolve } from "path";

const EXAMPLE_DIR = resolve(import.meta.dirname, "../../../examples/fastapi");
const PORT = 5002;
const ORIGIN = `http://localhost:${PORT}`;

export interface ServerHandle {
  baseUrl: string;
  origin: string;
  cleanup: () => Promise<void>;
}

export async function startFastAPI(): Promise<ServerHandle> {
  const proc: ChildProcess = spawn(
    "python",
    ["-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", String(PORT), "--no-access-log"],
    {
      cwd: EXAMPLE_DIR,
      stdio: "pipe",
      env: { ...process.env },
    },
  );

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
