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

// Site key for the CAP API endpoint
const CAP_KEY_ID = import.meta.env.VITE_CAP_KEY_ID || "";

let capWidget: CAPWidget | null = null;
let loadPromise: Promise<void> | null = null;

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
async function getCAPWidget(): Promise<CAPWidget> {
  if (capWidget) return capWidget;

  await loadCAPScript();

  if (!window.Cap) {
    throw new Error("CAP script loaded but Cap global not found");
  }

  capWidget = new window.Cap({ apiEndpoint: `/cap/${CAP_KEY_ID}/` });
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
  // If CAP is not configured, return empty string (server will reject if required)
  if (!CAP_KEY_ID) {
    console.warn("CAP_KEY_ID not configured, skipping proof-of-work");
    return "";
  }

  try {
    const widget = await getCAPWidget();
    const solution = await widget.solve();
    return solution.token;
  } catch (error) {
    console.error("CAP challenge failed:", error);
    throw new Error("Verification challenge failed. Please try again.");
  }
}
