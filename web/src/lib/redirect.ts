/**
 * Validates a redirect URL to prevent open redirect attacks.
 * Only allows relative paths that don't start with "//" (protocol-relative URLs).
 */
export function getSafeRedirect(redirectParam: string | null): string {
  const fallback = "/";

  if (!redirectParam) {
    return fallback;
  }

  // Decode to catch encoded bypass attempts
  let decoded: string;
  try {
    decoded = decodeURIComponent(redirectParam);
  } catch {
    return fallback;
  }

  // Must start with "/" but not "//" (protocol-relative URL)
  if (!decoded.startsWith("/") || decoded.startsWith("//")) {
    return fallback;
  }

  // Block URLs with embedded credentials or protocol
  if (decoded.includes("://") || decoded.includes("@")) {
    return fallback;
  }

  return decoded;
}
