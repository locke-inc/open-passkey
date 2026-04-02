<template>
  <div class="container">
    <h1>open-passkey</h1>
    <p class="subtitle">Nuxt + Vanilla JS Example</p>
    <div class="field">
      <label>User ID</label>
      <input v-model="userId" />
    </div>
    <div class="field">
      <label>Username</label>
      <input v-model="username" />
    </div>
    <div class="buttons">
      <button class="primary" :disabled="pending" @click="doRegister">
        {{ pending ? "Working..." : "Register Passkey" }}
      </button>
      <button class="secondary" :disabled="pending" @click="doLogin">
        {{ pending ? "Working..." : "Sign In" }}
      </button>
    </div>
    <div v-if="message" :class="['status', messageType]">{{ message }}</div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";

const BASE_URL = "/api/passkey";

const userId = ref("test-user");
const username = ref("Test User");
const pending = ref(false);
const message = ref("");
const messageType = ref<"success" | "error" | "info">("info");

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str: string): ArrayBuffer {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function showMessage(text: string, type: "success" | "error" | "info") {
  message.value = text;
  messageType.value = type;
}

async function doRegister() {
  pending.value = true;
  message.value = "";
  try {
    const beginRes = await fetch(`${BASE_URL}/register/begin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: userId.value, username: username.value }),
    });
    if (!beginRes.ok) {
      const err = await beginRes.json();
      throw new Error(err.error || "Failed to begin registration");
    }
    const options = await beginRes.json();

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: base64urlDecode(options.challenge),
        rp: options.rp,
        user: {
          id: base64urlDecode(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams,
        authenticatorSelection: options.authenticatorSelection,
        timeout: options.timeout,
        attestation: options.attestation || "none",
      },
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error("Credential creation cancelled");

    const response = credential.response as AuthenticatorAttestationResponse;
    const finishRes = await fetch(`${BASE_URL}/register/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: userId.value,
        credential: {
          id: credential.id,
          rawId: base64urlEncode(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: base64urlEncode(response.clientDataJSON),
            attestationObject: base64urlEncode(response.attestationObject),
          },
        },
      }),
    });
    if (!finishRes.ok) {
      const err = await finishRes.json();
      throw new Error(err.error || "Failed to finish registration");
    }
    showMessage("Passkey registered successfully!", "success");
  } catch (err: any) {
    showMessage(err.message || "Registration failed", "error");
  } finally {
    pending.value = false;
  }
}

async function doLogin() {
  pending.value = true;
  message.value = "";
  try {
    const beginRes = await fetch(`${BASE_URL}/login/begin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: userId.value }),
    });
    if (!beginRes.ok) {
      const err = await beginRes.json();
      throw new Error(err.error || "Failed to begin authentication");
    }
    const options = await beginRes.json();

    const getOptions: any = {
      publicKey: {
        challenge: base64urlDecode(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification || "preferred",
      },
    };
    if (options.allowCredentials) {
      getOptions.publicKey.allowCredentials = options.allowCredentials.map((c: any) => ({
        type: c.type,
        id: base64urlDecode(c.id),
      }));
    }

    const credential = (await navigator.credentials.get(getOptions)) as PublicKeyCredential | null;
    if (!credential) throw new Error("Authentication cancelled");

    const response = credential.response as AuthenticatorAssertionResponse;
    const finishPayload: any = {
      userId: userId.value || credential.id,
      credential: {
        id: credential.id,
        rawId: base64urlEncode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: base64urlEncode(response.clientDataJSON),
          authenticatorData: base64urlEncode(response.authenticatorData),
          signature: base64urlEncode(response.signature),
        },
      },
    };
    if (response.userHandle) {
      finishPayload.credential.response.userHandle = base64urlEncode(response.userHandle);
    }

    const finishRes = await fetch(`${BASE_URL}/login/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(finishPayload),
    });
    if (!finishRes.ok) {
      const err = await finishRes.json();
      throw new Error(err.error || "Failed to finish authentication");
    }
    const result = await finishRes.json();
    showMessage(`Authenticated! User: ${result.userId}`, "success");
  } catch (err: any) {
    showMessage(err.message || "Authentication failed", "error");
  } finally {
    pending.value = false;
  }
}
</script>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { max-width: 480px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }
h1 { font-size: 1.5rem; margin-bottom: 8px; }
.subtitle { color: #666; margin-bottom: 24px; font-size: 0.9rem; }
.field { margin-bottom: 12px; }
.field label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px; }
.field input { width: 100%; padding: 8px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 0.95rem; }
.buttons { display: flex; gap: 8px; margin-top: 16px; }
button { flex: 1; padding: 10px; border: none; border-radius: 6px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
.primary { background: #2563eb; color: #fff; }
.primary:hover { background: #1d4ed8; }
.secondary { background: #e5e7eb; color: #1a1a1a; }
.secondary:hover { background: #d1d5db; }
.status { margin-top: 20px; padding: 12px; border-radius: 6px; font-size: 0.9rem; }
.success { background: #d1fae5; color: #065f46; }
.error { background: #fee2e2; color: #991b1b; }
.info { background: #dbeafe; color: #1e40af; }
</style>
