import {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
} from "react";
import type { ReactNode } from "react";
import {
  PasskeyClient,
  type PasskeyClientConfig,
  type RegistrationResult,
  type AuthenticationResult,
} from "@open-passkey/sdk";

type Status = "idle" | "pending" | "success" | "error";

const PasskeyContext = createContext<PasskeyClient | null>(null);

function useClient(): PasskeyClient {
  const client = useContext(PasskeyContext);
  if (!client) {
    throw new Error(
      "usePasskeyRegister/usePasskeyLogin must be used within a <PasskeyProvider>"
    );
  }
  return client;
}

export interface PasskeyProviderProps extends PasskeyClientConfig {
  children: ReactNode;
}

export function PasskeyProvider({ children, ...config }: PasskeyProviderProps) {
  const client = useMemo(() => new PasskeyClient(config), [config.baseUrl, config.provider, config.rpId]);

  return (
    <PasskeyContext.Provider value={client}>
      {children}
    </PasskeyContext.Provider>
  );
}

export function usePasskeyRegister() {
  const client = useClient();
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<RegistrationResult | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const register = useCallback(
    async (userId: string, username: string) => {
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
    },
    [client]
  );

  return { register, status, result, error };
}

export function usePasskeyLogin() {
  const client = useClient();
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<AuthenticationResult | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const authenticate = useCallback(
    async (userId?: string) => {
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
    },
    [client]
  );

  return { authenticate, status, result, error };
}
