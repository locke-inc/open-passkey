import { writable } from "svelte/store";
import {
  PasskeyClient,
  type RegistrationResult,
  type AuthenticationResult,
} from "@open-passkey/sdk";

type Status = "idle" | "pending" | "success" | "error";

interface RegisterState {
  status: Status;
  result: RegistrationResult | null;
  error: Error | null;
}

interface LoginState {
  status: Status;
  result: AuthenticationResult | null;
  error: Error | null;
}

export function createPasskeyClient(config: { baseUrl: string }) {
  const client = new PasskeyClient({ baseUrl: config.baseUrl });

  function createRegisterStore() {
    const { subscribe, set, update } = writable<RegisterState>({
      status: "idle",
      result: null,
      error: null,
    });

    async function register(userId: string, username: string): Promise<void> {
      set({ status: "pending", result: null, error: null });
      try {
        const res = await client.register(userId, username);
        set({ status: "success", result: res, error: null });
      } catch (err) {
        set({
          status: "error",
          result: null,
          error: err instanceof Error ? err : new Error(String(err)),
        });
      }
    }

    return { subscribe, register };
  }

  function createLoginStore() {
    const { subscribe, set, update } = writable<LoginState>({
      status: "idle",
      result: null,
      error: null,
    });

    async function authenticate(userId?: string): Promise<void> {
      set({ status: "pending", result: null, error: null });
      try {
        const res = await client.authenticate(userId);
        set({ status: "success", result: res, error: null });
      } catch (err) {
        set({
          status: "error",
          result: null,
          error: err instanceof Error ? err : new Error(String(err)),
        });
      }
    }

    return { subscribe, authenticate };
  }

  return {
    registerStore: createRegisterStore(),
    loginStore: createLoginStore(),
  };
}
