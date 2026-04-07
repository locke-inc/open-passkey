import { useEffect, useState } from "react";
import { PasskeyProvider, usePasskeyRegister, usePasskeyLogin, usePasskeySession } from "@open-passkey/react";

function PasskeyDemo() {
  const [userId, setUserId] = useState("test-user");
  const [username, setUsername] = useState("Test User");
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error">("success");
  const { register, status: regStatus, error: regError } = usePasskeyRegister();
  const { authenticate, status: authStatus, error: authError } = usePasskeyLogin();
  const { session, loading, checkSession, logout } = usePasskeySession();

  useEffect(() => { checkSession(); }, [checkSession]);

  async function doRegister() {
    setMessage("");
    await register(userId, username);
  }

  async function doLogin() {
    setMessage("");
    await authenticate(userId);
    await checkSession();
  }

  async function doLogout() {
    await logout();
    setMessage("");
  }

  if (loading) return <div className="container"><p>Loading...</p></div>;

  if (session) {
    return (
      <div className="container">
        <h1>open-passkey</h1>
        <p className="subtitle">React Example</p>
        <div className="status success">Signed in as {session.userId}</div>
        <div className="buttons" style={{ marginTop: 16 }}>
          <button className="secondary" onClick={doLogout}>Sign Out</button>
        </div>
      </div>
    );
  }

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
        <button className="primary" onClick={doRegister} disabled={regStatus === "pending"}>
          {regStatus === "pending" ? "Registering..." : "Register Passkey"}
        </button>
        <button className="secondary" onClick={doLogin} disabled={authStatus === "pending"}>
          {authStatus === "pending" ? "Signing in..." : "Sign In"}
        </button>
      </div>
      {regStatus === "success" && <div className="status success">Registered! You can now sign in.</div>}
      {(regError || authError) && <div className="status error">{(regError || authError)?.message}</div>}
      {message && <div className={`status ${messageType}`}>{message}</div>}
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
