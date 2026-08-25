import { PasskeyProvider, usePasskeyRegister, usePasskeyLogin } from "@open-passkey/react";
import { useEffect, useState } from "react";

function PasskeyDemo() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error">("success");
  const { register, status: regStatus, error: regError } = usePasskeyRegister();
  const { authenticate, status: authStatus, error: authError } = usePasskeyLogin();
  async function doRegister() {
    setMessage("");
    if (!email) { setMessage("Please enter an email"); setMessageType("error"); return; }
    await register(email, email);
    setMessage("Authentication completed; the host application now establishes any session.");
  }

  async function doLogin() {
    setMessage("");
    await authenticate(email || undefined);
    setMessage("Authentication completed; the host application now establishes any session.");
  }
  useEffect(() => {
    if (regStatus === "success") { setMessage(""); }
    if (regError) { setMessage(regError.message); setMessageType("error"); }
  }, [regStatus, regError]);

  useEffect(() => {
    if (authError) { setMessage(authError.message); setMessageType("error"); }
  }, [authError]);

  return (
    <div className="page">
      <div className="card">
        <h1>open-passkey</h1>
        <p className="subtitle">Remix Example</p>
        <div className="field">
          <label>Email</label>
          <input type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="actions">
          <button className="btn-primary" onClick={doRegister} disabled={regStatus === "pending"}>
            {regStatus === "pending" ? "Creating..." : "Create Passkey"}
          </button>
          <div className="divider"><span>or</span></div>
          <button className="btn-secondary" onClick={doLogin} disabled={authStatus === "pending"}>
            {authStatus === "pending" ? "Signing in..." : "Sign in with Passkey"}
          </button>
        </div>
        {message && <div className={`status ${messageType}`}>{message}</div>}
      </div>
    </div>
  );
}

export default function Index() {
  return (
    <PasskeyProvider baseUrl="/api/passkey">
      <PasskeyDemo />
    </PasskeyProvider>
  );
}
