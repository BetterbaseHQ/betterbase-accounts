import { zxcvbn, zxcvbnOptions } from "@zxcvbn-ts/core";
import * as zxcvbnCommonPackage from "@zxcvbn-ts/language-common";
import * as zxcvbnEnPackage from "@zxcvbn-ts/language-en";

// Initialize zxcvbn with common patterns and English translations
zxcvbnOptions.setOptions({
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
  translations: zxcvbnEnPackage.translations,
});

// Common email domains for typo suggestions
const COMMON_DOMAINS = [
  // US/Global majors
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "ymail.com",
  "rocketmail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",

  // Privacy-focused
  "proton.me",
  "protonmail.com",
  "pm.me",
  "tutanota.com",
  "tutanota.de",
  "hey.com",
  "fastmail.com",
  "gmx.com",
  "gmx.de",
  "mail.com",

  // Russia
  "yandex.com",
  "yandex.ru",
  "yandex.ua",
  "mail.ru",
  "bk.ru",
  "inbox.ru",

  // China
  "qq.com",
  "163.com",
  "126.com",

  // Korea
  "naver.com",
  "daum.net",

  // India
  "rediffmail.com",

  // US ISPs
  "comcast.net",
  "verizon.net",
  "att.net",
  "bellsouth.net",

  // UK ISPs
  "btinternet.com",
  "virginmedia.com",
  "sky.com",

  // Germany
  "web.de",

  // France
  "orange.fr",
  "wanadoo.fr",
  "laposte.net",

  // Czech
  "seznam.cz",
  "centrum.cz",
];

// Levenshtein distance for typo detection
function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0]![j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i]![j] = matrix[i - 1]![j - 1]!;
      } else {
        matrix[i]![j] = Math.min(
          matrix[i - 1]![j - 1]! + 1,
          matrix[i]![j - 1]! + 1,
          matrix[i - 1]![j]! + 1,
        );
      }
    }
  }

  return matrix[b.length]![a.length]!;
}

export interface EmailValidationResult {
  valid: boolean;
  error?: string;
  suggestion?: string;
}

export function validateEmail(email: string): EmailValidationResult {
  if (!email || email.trim() === "") {
    return { valid: false, error: "Email is required" };
  }

  // Basic email format regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: "Please enter a valid email address" };
  }

  // Check for common typos in domain
  const [, domain] = email.toLowerCase().split("@");
  if (domain) {
    // Check if domain is already a common domain (exact match, case-insensitive)
    const isCommonDomain = COMMON_DOMAINS.some((d) => d.toLowerCase() === domain.toLowerCase());

    // Only check for typos if NOT already a common domain
    if (!isCommonDomain) {
      // Check for typos (Levenshtein distance <= 2)
      for (const commonDomain of COMMON_DOMAINS) {
        const distance = levenshteinDistance(domain, commonDomain);
        if (distance > 0 && distance <= 2) {
          const [localPart] = email.split("@") as [string, ...string[]];
          return {
            valid: true,
            suggestion: `${localPart.toLowerCase()}@${commonDomain}`,
          };
        }
      }
    }
  }

  return { valid: true };
}

export interface UsernameValidationResult {
  valid: boolean;
  error?: string;
}

export function validateUsername(username: string): UsernameValidationResult {
  if (!username || username.trim() === "") {
    return { valid: false, error: "Username is required" };
  }

  if (username.length < 3) {
    return { valid: false, error: "Username must be at least 3 characters" };
  }

  if (username.length > 32) {
    return { valid: false, error: "Username must be at most 32 characters" };
  }

  // Match server regex: ^[a-z0-9_]{3,32}$
  if (!/^[a-z0-9_]+$/.test(username)) {
    return {
      valid: false,
      error: "Username can only contain lowercase letters, numbers, and underscores",
    };
  }

  return { valid: true };
}

export interface PasswordValidationResult {
  valid: boolean;
  score: number; // 0-4 from zxcvbn
  error?: string;
  warning?: string;
  suggestions: string[];
}

// Minimum acceptable zxcvbn score (0-4 scale)
// 0-1 = Weak (rejected), 2 = Fair, 3 = Good, 4 = Strong
const MIN_PASSWORD_SCORE = 2;

export function validatePassword(password: string): PasswordValidationResult {
  if (!password) {
    return {
      valid: false,
      score: 0,
      error: "Password is required",
      suggestions: [],
    };
  }

  if (password.length < 8) {
    return {
      valid: false,
      score: 0,
      error: "Password must be at least 8 characters",
      suggestions: ["Use at least 8 characters"],
    };
  }

  const result = zxcvbn(password);
  const score = result.score; // 0-4

  const warning = result.feedback.warning || undefined;
  const suggestions = result.feedback.suggestions || [];

  // Require minimum strength score
  if (score < MIN_PASSWORD_SCORE) {
    // Use first suggestion as the error, or a fallback
    const error = suggestions[0] || "Password is too weak";
    return {
      valid: false,
      score,
      error,
      warning,
      suggestions,
    };
  }

  return {
    valid: true,
    score,
    warning,
    suggestions,
  };
}

export function getPasswordStrengthColor(score: number): string {
  switch (score) {
    case 0:
    case 1:
      return "bg-destructive";
    case 2:
      return "bg-orange-500";
    case 3:
      return "bg-yellow-500";
    case 4:
      return "bg-green-500";
    default:
      return "bg-muted";
  }
}

export function getPasswordStrengthLabel(score: number): string {
  switch (score) {
    case 0:
    case 1:
      return "Weak";
    case 2:
      return "Fair";
    case 3:
      return "Good";
    case 4:
      return "Strong";
    default:
      return "";
  }
}
