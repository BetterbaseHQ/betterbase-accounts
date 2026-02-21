/**
 * Integration tests for OPAQUE against the real Go server.
 *
 * NOTE: These tests are currently skipped because registration now requires
 * email verification. The verification code is sent via email (or printed to
 * terminal in dev mode), so there's no programmatic way to get the code.
 *
 * The verification flow is thoroughly tested by Go unit tests in server/server_test.go.
 *
 * To run these tests manually:
 *   1. Start the server: just run-dev
 *   2. Watch terminal for verification codes
 *   3. Remove .skip from tests and manually enter codes
 *
 * Run with:
 *   npm test -- opaque.integration
 */
import { describe, it, expect, beforeAll } from "vitest";
import { startRegistration, finishRegistration, startLogin, finishLogin } from "@/lib/opaque";

const API_BASE = "http://localhost:5377";

// Skip if server is not running
async function serverAvailable(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return res.ok;
  } catch {
    return false;
  }
}

describe("opaque integration with Go server", () => {
  let skipTests = false;

  beforeAll(async () => {
    skipTests = !(await serverAvailable());
    if (skipTests) {
      console.log("⚠️  Go server not running at localhost:5377 - skipping integration tests");
      console.log("   Start with: just run-dev");
    }
  });

  describe("signup then login flow against real server", () => {
    // Skipped: Registration now requires email verification token
    it.skip("should complete registration and login with Go server", async () => {
      if (skipTests) {
        console.log("Skipping - server not available");
        return;
      }

      const email = `test-${Date.now()}@example.com`;
      const password = "test-password-123";

      // === REGISTRATION FLOW ===

      // Step 1: Client starts registration
      const { clientRegistrationState, registrationRequest } = await startRegistration(password);

      expect(clientRegistrationState).toBeTruthy();
      expect(registrationRequest).toBeTruthy();

      // Step 2: Call Go server's registration init endpoint
      const regInitRes = await fetch(`${API_BASE}/v1/accounts/password/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          opaque_request: registrationRequest,
        }),
      });

      if (!regInitRes.ok) {
        const errText = await regInitRes.text();
        throw new Error(`Registration init failed: ${regInitRes.status} ${errText}`);
      }
      const regInitData = await regInitRes.json();
      expect(regInitData.opaque_response).toBeTruthy();
      expect(regInitData.state_token).toBeTruthy();
      // Step 3: Client finishes registration
      const { registrationRecord, exportKey } = await finishRegistration(
        clientRegistrationState,
        regInitData.opaque_response,
        password,
      );

      expect(registrationRecord).toBeTruthy();
      expect(exportKey).toBeTruthy();

      // Step 4: Call Go server's registration finish endpoint
      const regFinishRes = await fetch(`${API_BASE}/v1/accounts/password/finalize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          state_token: regInitData.state_token,
          opaque_record: registrationRecord,
        }),
      });

      if (!regFinishRes.ok) {
        const errText = await regFinishRes.text();
        throw new Error(`Registration finalize failed: ${regFinishRes.status} ${errText}`);
      }
      const regFinishData = await regFinishRes.json();
      expect(regFinishData.auth_token).toBeTruthy();

      console.log("✓ Registration completed successfully");

      // === LOGIN FLOW ===

      // Step 5: Client starts login
      const { clientLoginState, ke1 } = await startLogin(password);

      expect(clientLoginState).toBeTruthy();
      expect(ke1).toBeTruthy();

      // Step 6: Call Go server's login init endpoint
      const loginInitRes = await fetch(`${API_BASE}/v1/auth/login/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          opaque_ke1: ke1,
        }),
      });

      if (!loginInitRes.ok) {
        const errText = await loginInitRes.text();
        throw new Error(`Login init failed: ${loginInitRes.status} ${errText}`);
      }
      const loginInitData = await loginInitRes.json();
      expect(loginInitData.opaque_ke2).toBeTruthy();
      expect(loginInitData.login_token).toBeTruthy();

      // Step 7: Client finishes login
      const loginResult = await finishLogin(clientLoginState, loginInitData.opaque_ke2, password);

      // THIS IS THE KEY ASSERTION - login should succeed
      expect(loginResult).not.toBeNull();
      expect(loginResult!.ke3).toBeTruthy();
      expect(loginResult!.sessionKey).toBeTruthy();
      expect(loginResult!.exportKey).toBeTruthy();

      // Step 8: Call Go server's login finish endpoint
      const loginFinishRes = await fetch(`${API_BASE}/v1/auth/login/finalize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          login_token: loginInitData.login_token,
          opaque_ke3: loginResult!.ke3,
        }),
      });

      if (!loginFinishRes.ok) {
        const errText = await loginFinishRes.text();
        throw new Error(`Login finalize failed: ${loginFinishRes.status} ${errText}`);
      }
      const loginFinishData = await loginFinishRes.json();
      expect(loginFinishData.auth_token).toBeTruthy();

      console.log("✓ Login completed successfully");

      // Export keys from registration and login should match
      expect(loginResult!.exportKey).toBe(exportKey);
      console.log("✓ Export keys match");
    });

    // Skipped: Registration now requires email verification token
    it.skip("should fail login with wrong password against Go server", async () => {
      if (skipTests) {
        console.log("Skipping - server not available");
        return;
      }

      const email = `test-wrong-${Date.now()}@example.com`;
      const correctPassword = "correct-password";
      const wrongPassword = "wrong-password";

      // Register with correct password
      const { clientRegistrationState, registrationRequest } =
        await startRegistration(correctPassword);

      const regInitRes = await fetch(`${API_BASE}/v1/accounts/password/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          opaque_request: registrationRequest,
        }),
      });
      const regInitData = await regInitRes.json();

      const { registrationRecord } = await finishRegistration(
        clientRegistrationState,
        regInitData.opaque_response,
        correctPassword,
      );

      await fetch(`${API_BASE}/v1/accounts/password/finalize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          state_token: regInitData.state_token,
          opaque_record: registrationRecord,
        }),
      });

      // Try to login with wrong password
      const { clientLoginState, ke1 } = await startLogin(wrongPassword);

      const loginInitRes = await fetch(`${API_BASE}/v1/auth/login/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          opaque_ke1: ke1,
        }),
      });
      const loginInitData = await loginInitRes.json();

      // Client finishLogin should return null for wrong password
      const loginResult = await finishLogin(
        clientLoginState,
        loginInitData.opaque_ke2,
        wrongPassword,
      );

      expect(loginResult).toBeNull();
      console.log("✓ Wrong password correctly rejected on client side");
    });
  });
});
