import { describe, it, expect } from "vitest";
import {
  validateEmail,
  validateUsername,
  validatePassword,
  getPasswordStrengthColor,
  getPasswordStrengthLabel,
} from "@/lib/validation";

describe("validateEmail", () => {
  describe("valid emails", () => {
    it("accepts valid email addresses", () => {
      const validEmails = [
        "test@example.com",
        "user.name@domain.co.uk",
        "user+tag@example.org",
        "test123@test.io",
      ];

      validEmails.forEach((email) => {
        const result = validateEmail(email);
        expect(result.valid).toBe(true);
        expect(result.error).toBeUndefined();
      });
    });
  });

  describe("invalid emails", () => {
    it("rejects empty email", () => {
      const result = validateEmail("");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Email is required");
    });

    it("rejects whitespace-only email", () => {
      const result = validateEmail("   ");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Email is required");
    });

    it("rejects email without @", () => {
      const result = validateEmail("testexample.com");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Please enter a valid email address");
    });

    it("rejects email without domain", () => {
      const result = validateEmail("test@");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Please enter a valid email address");
    });

    it("rejects email without TLD", () => {
      const result = validateEmail("test@example");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Please enter a valid email address");
    });
  });

  describe("typo suggestions", () => {
    it("suggests gmail.com for gmal.com typo", () => {
      const result = validateEmail("test@gmal.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBe("test@gmail.com");
    });

    it("suggests gmail.com for gmali.com typo", () => {
      const result = validateEmail("test@gmali.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBe("test@gmail.com");
    });

    it("suggests yahoo.com for yahooo.com typo", () => {
      const result = validateEmail("user@yahooo.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBe("user@yahoo.com");
    });

    it("suggests proton.me for proton.me typo (prton.me)", () => {
      const result = validateEmail("test@prton.me");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBe("test@proton.me");
    });

    it("suggests fastmail.com for fastmai.com typo", () => {
      const result = validateEmail("test@fastmai.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBe("test@fastmail.com");
    });

    it("suggests icloud.com for iclud.com typo", () => {
      const result = validateEmail("test@iclud.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBe("test@icloud.com");
    });

    it("does not suggest for distance > 2", () => {
      const result = validateEmail("test@gm411.com"); // distance 3 from gmail.com (4 vs a, 1 vs i, 1 vs l)
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBeUndefined();
    });

    it("does not suggest for correct domain", () => {
      const result = validateEmail("test@gmail.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBeUndefined();
    });

    it("does not suggest for uncommon domain", () => {
      const result = validateEmail("test@mycompany.com");
      expect(result.valid).toBe(true);
      expect(result.suggestion).toBeUndefined();
    });
  });
});

describe("validateUsername", () => {
  describe("valid usernames", () => {
    it("accepts valid usernames", () => {
      const validUsernames = [
        "john",
        "john123",
        "john_doe",
        "john_doe123",
        "abc",
        "1john", // Can start with number (matches server)
        "_john", // Can start with underscore (matches server)
        "123", // All numbers
        "abcdefghij12345678901234567890ab", // 32 chars (max)
      ];

      validUsernames.forEach((username) => {
        const result = validateUsername(username);
        expect(result.valid).toBe(true);
        expect(result.error).toBeUndefined();
      });
    });
  });

  describe("invalid usernames", () => {
    it("rejects empty username", () => {
      const result = validateUsername("");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Username is required");
    });

    it("rejects whitespace-only username", () => {
      const result = validateUsername("   ");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Username is required");
    });

    it("rejects username shorter than 3 characters", () => {
      const result = validateUsername("ab");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Username must be at least 3 characters");
    });

    it("rejects username longer than 32 characters", () => {
      const result = validateUsername("abcdefghij12345678901234567890abc"); // 33 chars
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Username must be at most 32 characters");
    });

    it("rejects username with uppercase letters", () => {
      const result = validateUsername("John");
      expect(result.valid).toBe(false);
      expect(result.error).toBe(
        "Username can only contain lowercase letters, numbers, and underscores",
      );
    });

    it("rejects username with special characters", () => {
      const result = validateUsername("john@doe");
      expect(result.valid).toBe(false);
      expect(result.error).toBe(
        "Username can only contain lowercase letters, numbers, and underscores",
      );
    });

    it("rejects username with spaces", () => {
      const result = validateUsername("john doe");
      expect(result.valid).toBe(false);
      expect(result.error).toBe(
        "Username can only contain lowercase letters, numbers, and underscores",
      );
    });

    it("rejects username with dashes", () => {
      const result = validateUsername("john-doe");
      expect(result.valid).toBe(false);
      expect(result.error).toBe(
        "Username can only contain lowercase letters, numbers, and underscores",
      );
    });
  });
});

describe("validatePassword", () => {
  describe("valid passwords", () => {
    it("accepts strong passwords with 8+ characters", () => {
      const result = validatePassword("MyStr0ng!Pass");
      expect(result.valid).toBe(true);
    });

    it("accepts minimum 8 character password with sufficient complexity", () => {
      const result = validatePassword("C0mpl3x!Pass");
      expect(result.valid).toBe(true);
    });
  });

  describe("invalid passwords", () => {
    it("rejects empty password", () => {
      const result = validatePassword("");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Password is required");
    });

    it("rejects password shorter than 8 characters", () => {
      const result = validatePassword("1234567");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Password must be at least 8 characters");
    });

    it("rejects weak passwords despite meeting length requirement", () => {
      const result = validatePassword("password");
      expect(result.valid).toBe(false);
      // zxcvbn provides suggestions, we use the first one as the error
      expect(result.error).toBeTruthy();
      expect(result.suggestions.length).toBeGreaterThan(0);
    });

    it("rejects common passwords", () => {
      const result = validatePassword("password123");
      expect(result.valid).toBe(false);
    });

    it("rejects simple numeric passwords", () => {
      const result = validatePassword("12345678");
      expect(result.valid).toBe(false);
    });
  });

  describe("password strength", () => {
    it("returns score for rejected weak passwords", () => {
      const result = validatePassword("password");
      expect(result.score).toBeLessThanOrEqual(1);
      expect(result.valid).toBe(false);
    });

    it("returns higher score for stronger passwords", () => {
      const result = validatePassword("MyStr0ng!Pass#2024");
      expect(result.valid).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(3);
    });

    it("returns suggestions for weak passwords", () => {
      const result = validatePassword("password");
      expect(result.suggestions).toBeDefined();
      expect(result.suggestions.length).toBeGreaterThanOrEqual(0);
    });
  });
});

describe("getPasswordStrengthColor", () => {
  it("returns destructive color for score 0", () => {
    expect(getPasswordStrengthColor(0)).toBe("bg-destructive");
  });

  it("returns destructive color for score 1", () => {
    expect(getPasswordStrengthColor(1)).toBe("bg-destructive");
  });

  it("returns orange color for score 2", () => {
    expect(getPasswordStrengthColor(2)).toBe("bg-orange-500");
  });

  it("returns yellow color for score 3", () => {
    expect(getPasswordStrengthColor(3)).toBe("bg-yellow-500");
  });

  it("returns green color for score 4", () => {
    expect(getPasswordStrengthColor(4)).toBe("bg-green-500");
  });
});

describe("getPasswordStrengthLabel", () => {
  it("returns Weak for score 0", () => {
    expect(getPasswordStrengthLabel(0)).toBe("Weak");
  });

  it("returns Weak for score 1", () => {
    expect(getPasswordStrengthLabel(1)).toBe("Weak");
  });

  it("returns Fair for score 2", () => {
    expect(getPasswordStrengthLabel(2)).toBe("Fair");
  });

  it("returns Good for score 3", () => {
    expect(getPasswordStrengthLabel(3)).toBe("Good");
  });

  it("returns Strong for score 4", () => {
    expect(getPasswordStrengthLabel(4)).toBe("Strong");
  });

  it("returns empty string for invalid score", () => {
    expect(getPasswordStrengthLabel(-1)).toBe("");
    expect(getPasswordStrengthLabel(5)).toBe("");
  });
});
