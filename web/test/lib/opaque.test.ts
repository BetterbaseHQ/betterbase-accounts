import { describe, it, expect, beforeAll } from "vitest";
import * as opaque from "@serenity-kit/opaque";
import { startRegistration, finishRegistration, startLogin, finishLogin } from "@/lib/opaque";

// Must match Go server's ServerIdentity
const SERVER_IDENTITY = "less-accounts";

describe("opaque", () => {
  // Server setup string (contains all server key material)
  let serverSetup: string;

  beforeAll(async () => {
    await opaque.ready;
    // Generate server setup for testing
    serverSetup = opaque.server.createSetup();
  });

  // Helper to convert base64url to standard base64 (matching web client)
  function toStdBase64(input: string): string {
    let result = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = result.length % 4;
    if (pad) {
      result += "=".repeat(4 - pad);
    }
    return result;
  }

  // Helper to convert standard base64 to base64url
  function toBase64url(stdBase64: string): string {
    return stdBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  describe("signup then login flow", () => {
    it("should complete registration and then successfully login", async () => {
      const password = "test-password-123";
      const email = "test@example.com";

      // === REGISTRATION FLOW ===

      // Step 1: Client starts registration
      const { clientRegistrationState, registrationRequest } = await startRegistration(password);

      expect(clientRegistrationState).toBeTruthy();
      expect(registrationRequest).toBeTruthy();

      // Step 2: Server generates registration response
      // (Simulating what the Go server does - no identifiers)
      const serverRegResponse = opaque.server.createRegistrationResponse({
        serverSetup,
        registrationRequest: toBase64url(registrationRequest),
        userIdentifier: email,
      });
      // Step 3: Client finishes registration
      const { registrationRecord, exportKey } = await finishRegistration(
        clientRegistrationState,
        toStdBase64(serverRegResponse.registrationResponse),
        password,
      );

      expect(registrationRecord).toBeTruthy();
      expect(exportKey).toBeTruthy();

      // Store the record (simulating database storage)
      const storedRecord = registrationRecord;

      // === LOGIN FLOW ===

      // Step 4: Client starts login
      const { clientLoginState, ke1 } = await startLogin(password);

      expect(clientLoginState).toBeTruthy();
      expect(ke1).toBeTruthy();

      // Step 5: Server generates login response (KE2)
      // Server uses ServerIdentity during login (matching Go server's SetKeyMaterial)
      const serverLoginResponse = opaque.server.startLogin({
        serverSetup,
        registrationRecord: toBase64url(storedRecord),
        startLoginRequest: toBase64url(ke1),
        userIdentifier: email,
        identifiers: { server: SERVER_IDENTITY },
      });
      expect(serverLoginResponse.loginResponse).toBeTruthy();
      expect(serverLoginResponse.serverLoginState).toBeTruthy();

      // Step 6: Client finishes login
      const loginResult = await finishLogin(
        clientLoginState,
        toStdBase64(serverLoginResponse.loginResponse),
        password,
      );

      // THIS IS THE KEY ASSERTION - login should succeed
      expect(loginResult).not.toBeNull();
      expect(loginResult!.ke3).toBeTruthy();
      expect(loginResult!.sessionKey).toBeTruthy();
      expect(loginResult!.exportKey).toBeTruthy();

      // Step 7: Server verifies KE3
      const serverFinish = opaque.server.finishLogin({
        serverLoginState: serverLoginResponse.serverLoginState,
        finishLoginRequest: toBase64url(loginResult!.ke3),
        identifiers: { server: SERVER_IDENTITY },
      });

      // Server should successfully verify the login
      expect(serverFinish.sessionKey).toBeTruthy();

      // Export keys from registration and login should match
      expect(loginResult!.exportKey).toBe(exportKey);
    });

    it("should fail login with wrong password", async () => {
      const correctPassword = "correct-password";
      const wrongPassword = "wrong-password";
      const email = "test2@example.com";

      // Register with correct password
      const { clientRegistrationState, registrationRequest } =
        await startRegistration(correctPassword);

      const serverRegResponse = opaque.server.createRegistrationResponse({
        serverSetup,
        registrationRequest: toBase64url(registrationRequest),
        userIdentifier: email,
      });

      const { registrationRecord } = await finishRegistration(
        clientRegistrationState,
        toStdBase64(serverRegResponse.registrationResponse),
        correctPassword,
      );

      // Try to login with wrong password
      const { clientLoginState, ke1 } = await startLogin(wrongPassword);

      const serverLoginResponse = opaque.server.startLogin({
        serverSetup,
        registrationRecord: toBase64url(registrationRecord),
        startLoginRequest: toBase64url(ke1),
        userIdentifier: email,
        identifiers: { server: SERVER_IDENTITY },
      });

      // Client finishLogin should return null for wrong password
      const loginResult = await finishLogin(
        clientLoginState,
        toStdBase64(serverLoginResponse.loginResponse),
        wrongPassword,
      );

      expect(loginResult).toBeNull();
    });
  });
});
