/**
 * Browser-side WebAuthn passkey helpers.
 * Handles base64url conversion and the full registration/authentication ceremonies.
 * Works with any open-passkey server binding.
 */

function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str) {
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

async function registerPasskey(baseUrl, userId, username) {
  const beginRes = await fetch(`${baseUrl}/register/begin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, username }),
  });
  if (!beginRes.ok) {
    const err = await beginRes.json();
    throw new Error(err.error || "Failed to begin registration");
  }
  const options = await beginRes.json();

  const createOptions = {
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
  };

  if (options.extensions) {
    createOptions.publicKey.extensions = options.extensions;
  }

  const credential = await navigator.credentials.create(createOptions);
  if (!credential) throw new Error("Credential creation cancelled");

  const response = credential.response;
  const extensionResults = credential.getClientExtensionResults();
  const prfSupported = !!(extensionResults && extensionResults.prf && extensionResults.prf.enabled);

  const finishRes = await fetch(`${baseUrl}/register/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      userId,
      prfSupported,
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
  return finishRes.json();
}

async function authenticatePasskey(baseUrl, userId) {
  const beginRes = await fetch(`${baseUrl}/login/begin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId }),
  });
  if (!beginRes.ok) {
    const err = await beginRes.json();
    throw new Error(err.error || "Failed to begin authentication");
  }
  const options = await beginRes.json();

  const getOptions = {
    publicKey: {
      challenge: base64urlDecode(options.challenge),
      rpId: options.rpId,
      timeout: options.timeout,
      userVerification: options.userVerification || "preferred",
    },
  };

  if (options.allowCredentials) {
    getOptions.publicKey.allowCredentials = options.allowCredentials.map((c) => ({
      type: c.type,
      id: base64urlDecode(c.id),
    }));
  }

  if (options.extensions) {
    getOptions.publicKey.extensions = options.extensions;
  }

  const credential = await navigator.credentials.get(getOptions);
  if (!credential) throw new Error("Authentication cancelled");

  const response = credential.response;
  const finishPayload = {
    userId: userId || credential.id,
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

  const finishRes = await fetch(`${baseUrl}/login/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(finishPayload),
  });
  if (!finishRes.ok) {
    const err = await finishRes.json();
    throw new Error(err.error || "Failed to finish authentication");
  }
  return finishRes.json();
}
