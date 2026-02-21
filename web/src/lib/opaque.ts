import * as opaque from "@serenity-kit/opaque";

// Must match ServerIdentity in Go server (services/opaque.go)
const SERVER_IDENTITY = "less-accounts";

let initialized = false;

async function ensureReady() {
  if (!initialized) {
    await opaque.ready;
    initialized = true;
  }
}

// Convert base64url to standard base64 with padding (Go server expects standard base64)
function toStdBase64(input: string): string {
  // Replace base64url chars with standard base64 chars
  let result = input.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  const pad = result.length % 4;
  if (pad) {
    result += "=".repeat(4 - pad);
  }
  return result;
}

// Convert standard base64 to base64url without padding (JS library expects this)
function toBase64url(stdBase64: string): string {
  return stdBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function startRegistration(password: string) {
  await ensureReady();
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
    password,
  });
  return {
    clientRegistrationState,
    registrationRequest: toStdBase64(registrationRequest),
  };
}

export async function finishRegistration(
  clientRegistrationState: string,
  registrationResponse: string,
  password: string,
) {
  await ensureReady();
  const { registrationRecord, exportKey } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse: toBase64url(registrationResponse),
    password,
    identifiers: { server: SERVER_IDENTITY },
  });
  return {
    registrationRecord: toStdBase64(registrationRecord),
    exportKey,
  };
}

export async function startLogin(password: string) {
  await ensureReady();
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
    password,
  });
  return {
    clientLoginState,
    // Convert to standard base64 for Go server
    ke1: toStdBase64(startLoginRequest),
  };
}

export async function finishLogin(
  clientLoginState: string,
  loginResponse: string,
  password: string,
) {
  await ensureReady();
  const result = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: toBase64url(loginResponse),
    password,
    identifiers: { server: SERVER_IDENTITY },
  });
  if (!result) return null;
  return {
    ke3: toStdBase64(result.finishLoginRequest),
    sessionKey: result.sessionKey,
    exportKey: result.exportKey,
  };
}
