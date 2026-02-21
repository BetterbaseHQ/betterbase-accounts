import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Formats an error for display - capitalizes first letter */
export function formatError(err: unknown, fallback = "An error occurred"): string {
  const message = err instanceof Error ? err.message : fallback;
  return message.charAt(0).toUpperCase() + message.slice(1);
}
