"use client";
import { PasskeyProvider, usePasskeyRegister, usePasskeyLogin } from "@open-passkey/react";
import { useState } from "react";

function PasskeyDemo() {
  const [userId, setUserId] = useState("test-user");
  const [username, setUsername] = useState("Test User");
  const { register, status: regStatus, result: regResult, error: regError } = usePasskeyRegister();
  const { authenticate, status: authStatus, result: authResult, error: authError } = usePasskeyLogin();

  return (
    <div style={{ maxWidth: 480, margin: "40px auto", padding: "0 20px", fontFamily: "system-ui" }}>
      <h1>open-passkey</h1>
      <p style={{ color: "#666", marginBottom: 24 }}>Next.js + React Example</p>
      <div style={{ marginBottom: 12 }}>
        <label style={{ display: "block", fontWeight: 600, marginBottom: 4 }}>User ID</label>
        <input value={userId} onChange={(e) => setUserId(e.target.value)} style={{ width: "100%", padding: "8px 12px", border: "1px solid #ccc", borderRadius: 6 }} />
      </div>
      <div style={{ marginBottom: 12 }}>
        <label style={{ display: "block", fontWeight: 600, marginBottom: 4 }}>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ width: "100%", padding: "8px 12px", border: "1px solid #ccc", borderRadius: 6 }} />
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
        <button onClick={() => register(userId, username)} disabled={regStatus === "pending"} style={{ flex: 1, padding: 10, background: "#2563eb", color: "#fff", border: "none", borderRadius: 6, fontWeight: 600, cursor: "pointer" }}>
          {regStatus === "pending" ? "Registering..." : "Register Passkey"}
        </button>
        <button onClick={() => authenticate(userId)} disabled={authStatus === "pending"} style={{ flex: 1, padding: 10, background: "#e5e7eb", border: "none", borderRadius: 6, fontWeight: 600, cursor: "pointer" }}>
          {authStatus === "pending" ? "Signing in..." : "Sign In"}
        </button>
      </div>
      {regStatus === "success" && <div style={{ marginTop: 20, padding: 12, background: "#d1fae5", color: "#065f46", borderRadius: 6 }}>Registered!</div>}
      {authStatus === "success" && <div style={{ marginTop: 20, padding: 12, background: "#d1fae5", color: "#065f46", borderRadius: 6 }}>Authenticated! User: {authResult?.userId}</div>}
      {(regError || authError) && <div style={{ marginTop: 20, padding: 12, background: "#fee2e2", color: "#991b1b", borderRadius: 6 }}>{(regError || authError)?.message}</div>}
    </div>
  );
}

export default function Home() {
  return (
    <PasskeyProvider baseUrl="/api/passkey">
      <PasskeyDemo />
    </PasskeyProvider>
  );
}
