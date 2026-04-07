import { useState } from "react";
import { PasskeyProvider, usePasskeyRegister, usePasskeyLogin } from "@open-passkey/react";

function PasskeyDemo() {
  const [userId, setUserId] = useState("test-user");
  const [username, setUsername] = useState("Test User");
  const { register, status: regStatus, error: regError } = usePasskeyRegister();
  const { authenticate, status: authStatus, result: authResult, error: authError } = usePasskeyLogin();

  return (
    <div className="container">
      <h1>open-passkey</h1>
      <p className="subtitle">React Example</p>
      <div className="field">
        <label>User ID</label>
        <input value={userId} onChange={(e) => setUserId(e.target.value)} />
      </div>
      <div className="field">
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="buttons">
        <button className="primary" onClick={() => register(userId, username)} disabled={regStatus === "pending"}>
          {regStatus === "pending" ? "Registering..." : "Register Passkey"}
        </button>
        <button className="secondary" onClick={() => authenticate(userId)} disabled={authStatus === "pending"}>
          {authStatus === "pending" ? "Signing in..." : "Sign In"}
        </button>
      </div>
      {regStatus === "success" && <div className="status success">Registered!</div>}
      {authStatus === "success" && <div className="status success">Authenticated! User: {authResult?.userId}</div>}
      {(regError || authError) && <div className="status error">{(regError || authError)?.message}</div>}
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
