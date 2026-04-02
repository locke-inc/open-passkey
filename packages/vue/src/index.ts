import { ref, inject, provide, type Ref, type InjectionKey, type Plugin } from "vue";
import {
  PasskeyClient,
  type RegistrationResult,
  type AuthenticationResult,
} from "@open-passkey/sdk";

type Status = "idle" | "pending" | "success" | "error";

const PasskeyClientKey: InjectionKey<PasskeyClient> = Symbol("PasskeyClient");

function useClient(): PasskeyClient {
  const client = inject(PasskeyClientKey);
  if (!client) {
    throw new Error(
      "usePasskeyRegister/usePasskeyLogin requires the createPasskey plugin to be installed"
    );
  }
  return client;
}

export function createPasskey(config: { baseUrl: string }): Plugin {
  return {
    install(app) {
      const client = new PasskeyClient({ baseUrl: config.baseUrl });
      app.provide(PasskeyClientKey, client);
    },
  };
}

export function usePasskeyRegister() {
  const client = useClient();
  const status: Ref<Status> = ref("idle");
  const result: Ref<RegistrationResult | null> = ref(null);
  const error: Ref<Error | null> = ref(null);

  async function register(userId: string, username: string): Promise<void> {
    status.value = "pending";
    result.value = null;
    error.value = null;
    try {
      const res = await client.register(userId, username);
      result.value = res;
      status.value = "success";
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      status.value = "error";
    }
  }

  return { register, status, result, error };
}

export function usePasskeyLogin() {
  const client = useClient();
  const status: Ref<Status> = ref("idle");
  const result: Ref<AuthenticationResult | null> = ref(null);
  const error: Ref<Error | null> = ref(null);

  async function authenticate(userId?: string): Promise<void> {
    status.value = "pending";
    result.value = null;
    error.value = null;
    try {
      const res = await client.authenticate(userId);
      result.value = res;
      status.value = "success";
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      status.value = "error";
    }
  }

  return { authenticate, status, result, error };
}
