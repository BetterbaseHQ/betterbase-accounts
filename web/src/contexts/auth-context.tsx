import {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
  useRef,
  ReactNode,
} from "react";

interface AuthState {
  authToken: string | null;
  userId: string | null;
  email: string | null;
  exportKey: Uint8Array | null; // In-memory only, never persisted
  rootKey: Uint8Array | null; // In-memory only, never persisted
}

interface AuthContextValue extends AuthState {
  setAuth: (
    authToken: string,
    userId: string,
    email: string,
    exportKey: Uint8Array,
    rootKey: Uint8Array,
  ) => void;
  clearAuth: () => void;
  clearExportKey: () => void;
  hasExportKey: boolean;
  hasRootKey: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Best-effort secure clearing of sensitive key material.
 * While JavaScript doesn't guarantee memory clearing, zeroing the array
 * reduces the window of exposure.
 */
function secureClear(key: Uint8Array | null): void {
  if (key) {
    key.fill(0);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  // Initialize from localStorage for persisted values
  const [authToken, setAuthToken] = useState<string | null>(() =>
    localStorage.getItem("auth_token"),
  );
  const [userId, setUserId] = useState<string | null>(() => localStorage.getItem("user_id"));
  const [email, setEmail] = useState<string | null>(() => localStorage.getItem("user_email"));

  // Export key and root key are never persisted - only held in memory
  const [exportKey, setExportKey] = useState<Uint8Array | null>(null);
  const [rootKey, setRootKey] = useState<Uint8Array | null>(null);

  // Keep refs for secure clearing
  const exportKeyRef = useRef<Uint8Array | null>(null);
  const rootKeyRef = useRef<Uint8Array | null>(null);

  const setAuth = useCallback(
    (token: string, id: string, userEmail: string, key: Uint8Array, root: Uint8Array) => {
      // Clear any existing keys before setting new ones
      secureClear(exportKeyRef.current);
      secureClear(rootKeyRef.current);

      setAuthToken(token);
      setUserId(id);
      setEmail(userEmail);
      setExportKey(key);
      setRootKey(root);
      exportKeyRef.current = key;
      rootKeyRef.current = root;

      // Persist token, userId, and email to localStorage
      localStorage.setItem("auth_token", token);
      localStorage.setItem("user_id", id);
      localStorage.setItem("user_email", userEmail);
      // Export key and root key are intentionally NOT persisted
    },
    [],
  );

  const clearAuth = useCallback(() => {
    // Securely clear keys before nulling
    secureClear(exportKeyRef.current);
    secureClear(rootKeyRef.current);
    exportKeyRef.current = null;
    rootKeyRef.current = null;

    setAuthToken(null);
    setUserId(null);
    setEmail(null);
    setExportKey(null);
    setRootKey(null);

    localStorage.removeItem("auth_token");
    localStorage.removeItem("user_id");
    localStorage.removeItem("user_email");
  }, []);

  const clearExportKey = useCallback(() => {
    secureClear(exportKeyRef.current);
    secureClear(rootKeyRef.current);
    exportKeyRef.current = null;
    rootKeyRef.current = null;
    setExportKey(null);
    setRootKey(null);
  }, []);

  const value = useMemo(
    () => ({
      authToken,
      userId,
      email,
      exportKey,
      rootKey,
      setAuth,
      clearAuth,
      clearExportKey,
      hasExportKey: exportKey !== null,
      hasRootKey: rootKey !== null,
    }),
    [authToken, userId, email, exportKey, rootKey, setAuth, clearAuth, clearExportKey],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
