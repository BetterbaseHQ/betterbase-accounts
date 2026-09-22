// CAP (Proof-of-Work CAPTCHA) client module
// Lazy-loads the CAP script and provides a simple interface for solving challenges.

interface CAPWidget {
  solve(): Promise<{ token: string }>;
}

interface CapConstructor {
  new (options: { apiEndpoint: string }): CAPWidget;
}

declare global {
  interface Window {
    Cap?: CapConstructor;
  }
}

// CAP widget script (served via Caddy proxy in prod, Vite proxy in dev)
const CAP_SCRIPT_URL = "/cap/assets/widget.js";

// Site key baked at build time (dev). Image deployments provision the site
// key per deployment, so at runtime it is resolved from server discovery.
const BUILD_CAP_KEY_ID = import.meta.env.VITE_CAP_KEY_ID || "";

let capWidget: CAPWidget | null = null;
let loadPromise: Promise<void> | null = null;
let keyIdPromise: Promise<string> | null = null;

/**
 * Resolves the CAP site key id: build-time env first, then the server's
 * discovery metadata (`cap_key_id` is present when PoW is enabled).
 */
function resolveCapKeyId(): Promise<string> {
  if (BUILD_CAP_KEY_ID) return Promise.resolve(BUILD_CAP_KEY_ID);

  if (!keyIdPromise) {
    keyIdPromise = fetch("/.well-known/betterbase")
      .then((r) => (r.ok ? r.json() : Promise.resolve({})))
      .then((meta: { cap_key_id?: string }) => {
        const keyId = meta.cap_key_id ?? "";
        // Don't cache failures: a transient discovery error must not pin
        // "PoW unavailable" for the rest of the session.
        if (!keyId) keyIdPromise = null;
        return keyId;
      })
      .catch(() => {
        keyIdPromise = null;
        return "";
      });
  }
  return keyIdPromise;
}

/**
 * Loads the CAP script from the server.
 */
async function loadCAPScript(): Promise<void> {
  if (loadPromise) return loadPromise;

  loadPromise = new Promise((resolve, reject) => {
    if (window.Cap) {
      resolve();
      return;
    }

    const script = document.createElement("script");
    script.src = CAP_SCRIPT_URL;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load CAP script"));
    document.head.appendChild(script);
  });

  return loadPromise;
}

/**
 * Gets or creates the CAP widget.
 */
async function getCAPWidget(keyId: string): Promise<CAPWidget> {
  if (capWidget) return capWidget;

  await loadCAPScript();

  if (!window.Cap) {
    throw new Error("CAP script loaded but Cap global not found");
  }

  capWidget = new window.Cap({ apiEndpoint: `/cap/${keyId}/` });
  return capWidget;
}

/**
 * Solves a CAP challenge and returns the proof-of-work token.
 * The challenge runs in the background using the browser's Web Worker.
 *
 * @returns The CAP token to include in API requests
 * @throws Error if CAP is not configured or challenge fails
 */
export async function solveCAPChallenge(): Promise<string> {
  const keyId = await resolveCapKeyId();

  // If CAP is not configured, return empty string (server will reject if required)
  if (!keyId) {
    console.warn("CAP site key not configured, skipping proof-of-work");
    return "";
  }

  try {
    const widget = await getCAPWidget(keyId);
    const solution = await widget.solve();
    return solution.token;
  } catch (error) {
    console.error("CAP challenge failed:", error);
    throw new Error("Verification challenge failed. Please try again.");
  }
}
