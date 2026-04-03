<script>
  import { createPasskeyClient } from "@open-passkey/svelte";

  const { registerStore, loginStore } = createPasskeyClient({ baseUrl: "/api/passkey" });

  let userId = $state("test-user");
  let username = $state("Test User");
  let message = $state("");
  let messageType = $state("success");

  async function doRegister() {
    message = "";
    await registerStore.register(userId, username);
  }

  async function doLogin() {
    message = "";
    await loginStore.authenticate(userId);
  }

  $effect(() => {
    if ($registerStore.status === "success" && $registerStore.result) {
      message = `Registered! Credential ID: ${$registerStore.result.credentialId}`;
      messageType = "success";
    } else if ($registerStore.status === "error" && $registerStore.error) {
      message = $registerStore.error.message;
      messageType = "error";
    }
  });

  $effect(() => {
    if ($loginStore.status === "success" && $loginStore.result) {
      message = `Authenticated! User: ${$loginStore.result.userId}`;
      messageType = "success";
    } else if ($loginStore.status === "error" && $loginStore.error) {
      message = $loginStore.error.message;
      messageType = "error";
    }
  });
</script>

<svelte:head>
  <title>open-passkey SvelteKit Example</title>
</svelte:head>

<div class="container">
  <h1>open-passkey</h1>
  <p class="subtitle">SvelteKit + Svelte SDK Example</p>
  <div class="field">
    <label for="userId">User ID</label>
    <input id="userId" bind:value={userId} />
  </div>
  <div class="field">
    <label for="username">Username</label>
    <input id="username" bind:value={username} />
  </div>
  <div class="buttons">
    <button class="primary" disabled={$registerStore.status === "pending"} onclick={doRegister}>
      {$registerStore.status === "pending" ? "Registering..." : "Register Passkey"}
    </button>
    <button class="secondary" disabled={$loginStore.status === "pending"} onclick={doLogin}>
      {$loginStore.status === "pending" ? "Signing in..." : "Sign In"}
    </button>
  </div>
  {#if message}
    <div class="status {messageType}">{message}</div>
  {/if}
</div>

<style>
  :global(*) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
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
