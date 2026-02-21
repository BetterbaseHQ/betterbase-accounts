const BASE_URL = import.meta.env.VITE_API_URL || "";

type ErrorPayload = {
  error?: string;
  error_description?: string;
};

async function readResponseText(response: Response): Promise<string> {
  if (typeof response.text === "function") {
    return response.text();
  }

  const responseWithJson = response as { json?: () => Promise<unknown> };
  if (typeof responseWithJson.json === "function") {
    const jsonText = JSON.stringify(await responseWithJson.json());
    return jsonText || "";
  }

  return "";
}

async function parseErrorMessage(response: Response): Promise<string> {
  const defaultMessage = `Request failed (${response.status})`;

  const text = await readResponseText(response);
  if (!text) {
    return defaultMessage;
  }

  try {
    const error = JSON.parse(text) as ErrorPayload;
    return error.error || error.error_description || text;
  } catch {
    return text;
  }
}

async function parseJsonResponse<T>(response: Response, allowEmpty = false): Promise<T> {
  const text = await readResponseText(response);
  if (!text) {
    if (!allowEmpty) {
      throw new Error("Empty response body");
    }
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

function requestHeaders(token?: string): Record<string, string> {
  if (!token) {
    return { "Content-Type": "application/json" };
  }
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

function getAuthToken(): string {
  return localStorage.getItem("auth_token") || "";
}

async function request<T>(
  path: string,
  method: "POST" | "PUT",
  body: unknown,
  token?: string,
  allowEmpty = false,
): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: requestHeaders(token),
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(await parseErrorMessage(res));
  }

  return parseJsonResponse<T>(res, allowEmpty);
}

async function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, "POST", body, undefined, true);
}

async function postAuth<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, "POST", body, getAuthToken(), true);
}

async function getAuth<T>(path: string, token?: string): Promise<T> {
  const effectiveToken = token || getAuthToken();

  const res = await fetch(`${BASE_URL}${path}`, {
    method: "GET",
    ...(effectiveToken && {
      headers: {
        Authorization: `Bearer ${effectiveToken}`,
      },
    }),
  });

  if (!res.ok) {
    throw new Error(await parseErrorMessage(res));
  }

  return parseJsonResponse<T>(res);
}

async function putAuth<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, "PUT", body, getAuthToken(), true);
}

async function postWithToken<T>(path: string, body: unknown, token: string): Promise<T> {
  return request<T>(path, "POST", body, token, false);
}

export const api = {
  sendVerificationCode: (
    email: string,
    purpose: "registration" | "recovery",
    capToken?: string,
    username?: string,
  ) =>
    post<void>("/v1/accounts/verify/send", {
      email,
      purpose,
      cap_token: capToken || "",
      username,
    }),

  confirmVerificationCode: (email: string, code: string, purpose: "registration" | "recovery") =>
    post<{ verification_token: string }>("/v1/accounts/verify/confirm", {
      email,
      code,
      purpose,
    }),

  registerInit: (
    username: string,
    email: string,
    opaqueRequest: string,
    verificationToken: string,
    capToken?: string,
  ) =>
    post<{ opaque_response: string; state_token: string; user_id: string }>(
      "/v1/accounts/password/init",
      {
        username,
        email,
        opaque_request: opaqueRequest,
        verification_token: verificationToken,
        cap_token: capToken || "",
      },
    ),

  registerFinalize: (stateToken: string, opaqueRecord: string, wrappedRootKey: string) =>
    post<{ auth_token: string; user_id: string }>("/v1/accounts/password/finalize", {
      state_token: stateToken,
      opaque_record: opaqueRecord,
      wrapped_root_key: wrappedRootKey,
    }),

  loginInit: (username: string, opaqueKe1: string, capToken?: string) =>
    post<{ opaque_ke2: string; login_token: string }>("/v1/auth/login/init", {
      username,
      opaque_ke1: opaqueKe1,
      cap_token: capToken || "",
    }),

  loginFinalize: (loginToken: string, opaqueKe3: string) =>
    post<{ auth_token: string; user_id: string }>("/v1/auth/login/finalize", {
      login_token: loginToken,
      opaque_ke3: opaqueKe3,
    }),

  oauthConsent: (
    oauthState: string,
    approved: boolean,
    keysJWE?: string,
    keysJWKThumbprint?: string,
    appKeypairBlob?: string,
    appPublicKeyJwk?: string,
    wrappedScopedKey?: string,
  ) =>
    postAuth<{ redirect_uri: string }>("/oauth/consent", {
      oauth_state: oauthState,
      approved,
      ...(keysJWE && { keys_jwe: keysJWE }),
      ...(keysJWKThumbprint && { keys_jwk_thumbprint: keysJWKThumbprint }),
      ...(appKeypairBlob && { app_keypair_blob: appKeypairBlob }),
      ...(appPublicKeyJwk && { app_public_key_jwk: appPublicKeyJwk }),
      ...(wrappedScopedKey && { wrapped_scoped_key: wrappedScopedKey }),
    }),

  getGrantKeypairBlob: (clientId: string) =>
    getAuth<{ app_keypair_blob: string; wrapped_scoped_key?: string }>(
      `/oauth/grant-keypair?client_id=${encodeURIComponent(clientId)}`,
    ),

  storeRecoveryBlob: (blob: string) => postAuth<void>("/v1/accounts/recovery-blob", { blob }),

  getRecoveryBlob: (email: string, verificationToken: string) =>
    postWithToken<{ blob: string }>(
      "/v1/accounts/recovery-blob/fetch",
      {
        email,
      },
      verificationToken,
    ),

  recoverInit: (
    email: string,
    opaqueRequest: string,
    verificationToken: string,
    capToken?: string,
  ) =>
    post<{ opaque_response: string; state_token: string; user_id: string }>(
      "/v1/accounts/recover/init",
      {
        email,
        opaque_request: opaqueRequest,
        verification_token: verificationToken,
        cap_token: capToken || "",
      },
    ),

  recoverFinalize: (
    stateToken: string,
    opaqueRecord: string,
    wrappedRootKey: string,
    newBlob?: string,
  ) =>
    post<{ auth_token: string; user_id: string }>("/v1/accounts/recover/finalize", {
      state_token: stateToken,
      opaque_record: opaqueRecord,
      wrapped_root_key: wrappedRootKey,
      ...(newBlob && { new_blob: newBlob }),
    }),

  getRootKey: (token?: string) =>
    getAuth<{ wrapped_root_key: string }>("/v1/accounts/root-key", token),

  setRootKey: (wrappedRootKey: string) =>
    putAuth<void>("/v1/accounts/root-key", { wrapped_root_key: wrappedRootKey }),

  getGrantWrappedKeys: () =>
    getAuth<{ grants: Array<{ grant_id: string; client_id: string; wrapped_scoped_key: string }> }>(
      "/v1/accounts/grants/wrapped-keys",
    ),

  updateGrantWrappedKeys: (grants: Array<{ grant_id: string; wrapped_scoped_key: string }>) =>
    putAuth<void>("/v1/accounts/grants/wrapped-keys", { grants }),

  rotateRootKey: (
    wrappedRootKey: string,
    grants: Array<{ grant_id: string; wrapped_scoped_key: string }>,
    recoveryBlob?: string,
  ) =>
    postAuth<void>("/v1/accounts/rotate-root-key", {
      wrapped_root_key: wrappedRootKey,
      grants,
      ...(recoveryBlob && { recovery_blob: recoveryBlob }),
    }),

  passwordChangeInit: (username: string, opaqueKe1: string) =>
    postAuth<{ opaque_ke2: string; login_token: string }>("/v1/accounts/password/change/init", {
      username,
      opaque_ke1: opaqueKe1,
    }),

  passwordChangeVerify: (loginToken: string, opaqueKe3: string, opaqueRequest: string) =>
    postAuth<{ opaque_response: string; state_token: string }>(
      "/v1/accounts/password/change/verify",
      { login_token: loginToken, opaque_ke3: opaqueKe3, opaque_request: opaqueRequest },
    ),

  passwordChangeComplete: (stateToken: string, opaqueRecord: string, wrappedRootKey: string) =>
    postAuth<{ auth_token: string; user_id: string }>("/v1/accounts/password/change/complete", {
      state_token: stateToken,
      opaque_record: opaqueRecord,
      wrapped_root_key: wrappedRootKey,
    }),
};
