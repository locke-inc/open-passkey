import { createSignal, onMount, Show } from "solid-js";
import { PasskeyProvider, createPasskeyRegister, createPasskeyLogin, createPasskeySession } from "@open-passkey/solid";

function PasskeyDemo() {
  const [email, setEmail] = createSignal("");
  const [message, setMessage] = createSignal("");
  const [messageType, setMessageType] = createSignal<"success" | "error">("success");

  const { register, status: regStatus, error: regError } = createPasskeyRegister();
  const { authenticate, status: authStatus, error: authError } = createPasskeyLogin();
  const { session, loading, checkSession, logout } = createPasskeySession();

  onMount(() => checkSession());

  async function doRegister() {
    setMessage("");
    if (!email()) { setMessage("Please enter an email"); setMessageType("error"); return; }
    await register(email(), email());
    if (regError()) {
      setMessage(regError()!.message);
      setMessageType("error");
    } else {
      await checkSession();
    }
  }

  async function doLogin() {
    setMessage("");
    await authenticate(email() || undefined);
    if (authError()) {
      setMessage(authError()!.message);
      setMessageType("error");
    } else {
      await checkSession();
    }
  }

  async function doLogout() {
    await logout();
    setMessage("");
  }

  return (
    <div class="page">
      <div class="card">
        <h1>open-passkey</h1>
        <p class="subtitle">SolidJS Example</p>

        <Show when={!loading()} fallback={<div class="loading">Loading...</div>}>
          <Show when={session()} fallback={
            <>
              <div class="field">
                <label>Email</label>
                <input type="email" placeholder="you@example.com" value={email()} onInput={(e) => setEmail(e.currentTarget.value)} />
              </div>
              <div class="actions">
                <button class="btn-primary" onClick={doRegister} disabled={regStatus() === "pending"}>
                  {regStatus() === "pending" ? "Creating..." : "Create Passkey"}
                </button>
                <div class="divider"><span>or</span></div>
                <button class="btn-secondary" onClick={doLogin} disabled={authStatus() === "pending"}>
                  {authStatus() === "pending" ? "Signing in..." : "Sign in with Passkey"}
                </button>
              </div>
              <Show when={message()}>
                <div class={`status ${messageType()}`}>{message()}</div>
              </Show>
            </>
          }>
            <div class="signed-in">
              <div class="signed-in-badge">Authenticated</div>
              <div class="signed-in-email">{session()!.userId}</div>
              <button class="btn-secondary" onClick={doLogout}>Sign Out</button>
            </div>
          </Show>
        </Show>
      </div>
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
