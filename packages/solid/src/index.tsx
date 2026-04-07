import {
  createSignal,
  createContext,
  useContext,
  type Accessor,
  type JSX,
} from "solid-js";
import {
  PasskeyClient,
  type PasskeyClientConfig,
  type RegistrationResult,
  type AuthenticationResult,
} from "@open-passkey/sdk";

type Status = "idle" | "pending" | "success" | "error";

const PasskeyContext = createContext<PasskeyClient>();

export interface PasskeyProviderProps extends PasskeyClientConfig {
  children: JSX.Element;
}

export function PasskeyProvider(props: PasskeyProviderProps) {
  const client = new PasskeyClient(props);

  return (
    <PasskeyContext.Provider value={client}>
      {props.children}
    </PasskeyContext.Provider>
  );
}

function useClient(): PasskeyClient {
  const client = useContext(PasskeyContext);
  if (!client) {
    throw new Error(
      "createPasskeyRegister/createPasskeyLogin must be used within a <PasskeyProvider>"
    );
  }
  return client;
}

export function createPasskeyRegister() {
  const client = useClient();
  const [status, setStatus] = createSignal<Status>("idle");
  const [result, setResult] = createSignal<RegistrationResult | null>(null);
  const [error, setError] = createSignal<Error | null>(null);

  async function register(userId: string, username: string): Promise<void> {
    setStatus("pending");
    setResult(null);
    setError(null);
    try {
      const res = await client.register(userId, username);
      setResult(res);
      setStatus("success");
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setStatus("error");
    }
  }

  return { register, status: status as Accessor<Status>, result: result as Accessor<RegistrationResult | null>, error: error as Accessor<Error | null> };
}

export function createPasskeyLogin() {
  const client = useClient();
  const [status, setStatus] = createSignal<Status>("idle");
  const [result, setResult] = createSignal<AuthenticationResult | null>(null);
  const [error, setError] = createSignal<Error | null>(null);

  async function authenticate(userId?: string): Promise<void> {
    setStatus("pending");
    setResult(null);
    setError(null);
    try {
      const res = await client.authenticate(userId);
      setResult(res);
      setStatus("success");
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setStatus("error");
    }
  }

  return { authenticate, status: status as Accessor<Status>, result: result as Accessor<AuthenticationResult | null>, error: error as Accessor<Error | null> };
}

export function createPasskeySession() {
  const client = useClient();
  const [session, setSession] = createSignal<AuthenticationResult | null>(null);
  const [loading, setLoading] = createSignal(true);

  async function checkSession(): Promise<void> {
    setLoading(true);
    try {
      const result = await client.getSession();
      setSession(result);
    } finally {
      setLoading(false);
    }
  }

  async function logout(): Promise<void> {
    await client.logout();
    setSession(null);
  }

  return {
    session: session as Accessor<AuthenticationResult | null>,
    loading: loading as Accessor<boolean>,
    checkSession,
    logout,
  };
}
