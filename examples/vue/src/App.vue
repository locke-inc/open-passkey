<template>
  <div class="container">
    <h1>open-passkey</h1>
    <p class="subtitle">Vue Example</p>

    <div v-if="sessionLoading">
      <p>Loading...</p>
    </div>

    <template v-else-if="session">
      <div class="status success">Signed in as {{ session.userId }}</div>
      <div class="buttons" style="margin-top: 16px">
        <button class="secondary" @click="doLogout">Sign Out</button>
      </div>
    </template>

    <template v-else>
      <div class="field">
        <label>User ID</label>
        <input v-model="userId" />
      </div>
      <div class="field">
        <label>Username</label>
        <input v-model="username" />
      </div>
      <div class="buttons">
        <button class="primary" :disabled="regStatus === 'pending'" @click="doRegister">
          {{ regStatus === "pending" ? "Registering..." : "Register Passkey" }}
        </button>
        <button class="secondary" :disabled="authStatus === 'pending'" @click="doLogin">
          {{ authStatus === "pending" ? "Signing in..." : "Sign In" }}
        </button>
      </div>
      <div v-if="message" :class="['status', messageType]">{{ message }}</div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from "vue";
import { usePasskeyRegister, usePasskeyLogin, usePasskeySession } from "@open-passkey/vue";

const userId = ref("test-user");
const username = ref("Test User");
const message = ref("");
const messageType = ref<"success" | "error">("success");

const { register, status: regStatus, result: regResult, error: regError } = usePasskeyRegister();
const { authenticate, status: authStatus, error: authError } = usePasskeyLogin();
const { session, loading: sessionLoading, checkSession, logout } = usePasskeySession();

onMounted(() => checkSession());

async function doRegister() {
  message.value = "";
  await register(userId.value, username.value);
}

async function doLogin() {
  message.value = "";
  await authenticate(userId.value);
  await checkSession();
}

async function doLogout() {
  await logout();
  message.value = "";
}

watch(regStatus, (s) => {
  if (s === "success" && regResult.value) {
    message.value = "Registered! You can now sign in.";
    messageType.value = "success";
  } else if (s === "error" && regError.value) {
    message.value = regError.value.message;
    messageType.value = "error";
  }
});

watch(authStatus, (s) => {
  if (s === "error" && authError.value) {
    message.value = authError.value.message;
    messageType.value = "error";
  }
});
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
.primary:hover:not(:disabled) { background: #1d4ed8; }
.secondary { background: #e5e7eb; color: #1a1a1a; }
.secondary:hover:not(:disabled) { background: #d1d5db; }
button:disabled { opacity: 0.6; cursor: not-allowed; }
.status { margin-top: 20px; padding: 12px; border-radius: 6px; font-size: 0.9rem; }
.success { background: #d1fae5; color: #065f46; }
.error { background: #fee2e2; color: #991b1b; }
</style>
