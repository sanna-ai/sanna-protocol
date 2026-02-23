import { describe, it, expect } from "vitest";
import { redactPII, redactInObject } from "../src/pii.js";
import type { PiiPattern } from "../src/pii.js";

describe("redactPII", () => {
  it("should redact email addresses", () => {
    const result = redactPII("Contact alice@example.com for info");
    expect(result.redacted).toContain("[EMAIL_REDACTED]");
    expect(result.redacted).not.toContain("alice@example.com");
    expect(result.redaction_count).toBe(1);
    expect(result.redacted_types).toContain("email");
  });

  it("should redact multiple emails", () => {
    const result = redactPII("From: a@b.com To: c@d.com");
    expect(result.redaction_count).toBe(2);
  });

  it("should redact SSN patterns", () => {
    const result = redactPII("SSN: 123-45-6789");
    expect(result.redacted).toContain("[SSN_REDACTED]");
    expect(result.redacted).not.toContain("123-45-6789");
    expect(result.redacted_types).toContain("ssn");
  });

  it("should redact phone numbers", () => {
    const result = redactPII("Call (555) 123-4567");
    expect(result.redacted).toContain("[PHONE_REDACTED]");
    expect(result.redaction_count).toBeGreaterThanOrEqual(1);
  });

  it("should redact IP addresses", () => {
    const result = redactPII("Server at 192.168.1.100");
    expect(result.redacted).toContain("[IP_REDACTED]");
    expect(result.redacted).not.toContain("192.168.1.100");
  });

  it("should redact credit card numbers", () => {
    const result = redactPII("Card: 4111 1111 1111 1111");
    expect(result.redacted).toContain("[CC_REDACTED]");
    expect(result.redacted).not.toContain("4111");
  });

  it("should not produce false positives on normal text", () => {
    const result = redactPII("Hello world, this is a normal sentence.");
    expect(result.redaction_count).toBe(0);
    expect(result.redacted).toBe("Hello world, this is a normal sentence.");
  });

  it("should handle empty string", () => {
    const result = redactPII("");
    expect(result.redacted).toBe("");
    expect(result.redaction_count).toBe(0);
  });

  it("should apply custom patterns", () => {
    const custom: PiiPattern[] = [
      {
        name: "api_key",
        regex: /sk-[a-zA-Z0-9]{20,}/g,
        replacement: "[API_KEY_REDACTED]",
      },
    ];
    const result = redactPII(
      "Key: sk-abcdefghijklmnopqrstuvwxyz",
      custom,
    );
    expect(result.redacted).toContain("[API_KEY_REDACTED]");
    expect(result.redacted_types).toContain("api_key");
  });

  it("should redact multiple types in one string", () => {
    const result = redactPII(
      "Email alice@example.com from 10.0.0.1",
    );
    expect(result.redacted_types).toContain("email");
    expect(result.redacted_types).toContain("ip_address");
    expect(result.redaction_count).toBeGreaterThanOrEqual(2);
  });
});

describe("redactInObject", () => {
  it("should redact strings in a flat object", () => {
    const result = redactInObject({
      name: "Alice",
      email: "alice@example.com",
    }) as Record<string, string>;
    expect(result.email).toContain("[EMAIL_REDACTED]");
    expect(result.name).toBe("Alice");
  });

  it("should redact strings in nested objects", () => {
    const result = redactInObject({
      user: { contact: { email: "bob@test.com" } },
    }) as any;
    expect(result.user.contact.email).toContain("[EMAIL_REDACTED]");
  });

  it("should redact strings in arrays", () => {
    const result = redactInObject(["alice@test.com", "normal text"]) as string[];
    expect(result[0]).toContain("[EMAIL_REDACTED]");
    expect(result[1]).toBe("normal text");
  });

  it("should pass through non-string values", () => {
    const result = redactInObject({ count: 42, active: true }) as any;
    expect(result.count).toBe(42);
    expect(result.active).toBe(true);
  });

  it("should handle null and undefined", () => {
    expect(redactInObject(null)).toBeNull();
    expect(redactInObject(undefined)).toBeUndefined();
  });
});
