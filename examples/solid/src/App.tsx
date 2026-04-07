import { createSignal, Show } from "solid-js";
import { PasskeyProvider, createPasskeyRegister, createPasskeyLogin } from "@open-passkey/solid";

function PasskeyDemo() {
  const [userId, setUserId] = createSignal("test-user");
  const [username, setUsername] = createSignal("Test User");
  const [message, setMessage] = createSignal("");
  const [messageType, setMessageType] = createSignal<"success" | "error">("success");

  const { register, status: regStatus, error: regError } = createPasskeyRegister();
  const { authenticate, status: authStatus, result: authResult, error: authError } = createPasskeyLogin();

  async function doRegister() {
    setMessage("");
    await register(userId(), username());
    if (regError()) {
      setMessage(regError()!.message);
      setMessageType("error");
    } else {
      setMessage("Passkey registered successfully!");
      setMessageType("success");
    }
  }

  async function doLogin() {
    setMessage("");
    await authenticate(userId());
    if (authError()) {
      setMessage(authError()!.message);
      setMessageType("error");
    } else if (authResult()) {
      setMessage(`Authenticated! User: ${authResult()!.userId}`);
      setMessageType("success");
    }
  }

  return (
    <div class="container">
      <h1>open-passkey</h1>
      <p class="subtitle">SolidJS Example</p>
      <div class="field">
        <label>User ID</label>
        <input value={userId()} onInput={(e) => setUserId(e.currentTarget.value)} />
      </div>
      <div class="field">
        <label>Username</label>
        <input value={username()} onInput={(e) => setUsername(e.currentTarget.value)} />
      </div>
      <div class="buttons">
        <button class="primary" onClick={doRegister} disabled={regStatus() === "pending"}>
          {regStatus() === "pending" ? "Registering..." : "Register Passkey"}
        </button>
        <button class="secondary" onClick={doLogin} disabled={authStatus() === "pending"}>
          {authStatus() === "pending" ? "Signing in..." : "Sign In"}
        </button>
      </div>
      <Show when={message()}>
        <div class={`status ${messageType()}`}>{message()}</div>
      </Show>
    </div>
  );
}

export function App() {
  return (
    <PasskeyProvider provider="locke-gateway" rpId="localhost">
      <PasskeyDemo />
    </PasskeyProvider>
  );
}
