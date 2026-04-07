import { writable } from "svelte/store";
import {
  PasskeyClient,
  type PasskeyClientConfig,
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

export function createPasskeyClient(config: PasskeyClientConfig) {
  const client = new PasskeyClient(config);

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

  function createSessionStore() {
    const { subscribe, set } = writable<{
      session: AuthenticationResult | null;
      loading: boolean;
    }>({ session: null, loading: true });

    async function checkSession(): Promise<void> {
      set({ session: null, loading: true });
      try {
        const result = await client.getSession();
        set({ session: result, loading: false });
      } catch {
        set({ session: null, loading: false });
      }
    }

    async function logout(): Promise<void> {
      await client.logout();
      set({ session: null, loading: false });
    }

    return { subscribe, checkSession, logout };
  }

  return {
    registerStore: createRegisterStore(),
    loginStore: createLoginStore(),
    sessionStore: createSessionStore(),
  };
}
