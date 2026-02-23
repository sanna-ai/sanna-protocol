/**
 * Sanna Gateway — PII Redaction
 *
 * Pattern-based detection and redaction of personally identifiable
 * information in tool inputs and outputs.
 */

// ── Built-in patterns ────────────────────────────────────────────────

export interface PiiPattern {
  name: string;
  regex: RegExp;
  replacement: string;
}

const BUILTIN_PATTERNS: PiiPattern[] = [
  {
    name: "email",
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replacement: "[EMAIL_REDACTED]",
  },
  {
    name: "ssn",
    // SSN: XXX-XX-XXXX (with separators)
    regex: /\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b/g,
    replacement: "[SSN_REDACTED]",
  },
  {
    name: "credit_card",
    // Credit card: 13-19 digits, optionally separated by spaces or dashes
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: "[CC_REDACTED]",
  },
  {
    name: "phone",
    // US/international phone formats
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[PHONE_REDACTED]",
  },
  {
    name: "ip_address",
    // IPv4 address
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    replacement: "[IP_REDACTED]",
  },
];

// ── Redaction results ────────────────────────────────────────────────

export interface RedactionResult {
  redacted: string;
  redaction_count: number;
  redacted_types: string[];
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Redact PII from a text string.
 *
 * Applies built-in patterns plus any custom patterns provided.
 * Returns the redacted text along with counts and types of redactions.
 */
export function redactPII(
  text: string,
  customPatterns?: PiiPattern[],
): RedactionResult {
  const patterns = [...BUILTIN_PATTERNS, ...(customPatterns ?? [])];
  let result = text;
  let totalCount = 0;
  const typesFound = new Set<string>();

  for (const pattern of patterns) {
    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;
    const matches = result.match(pattern.regex);
    if (matches && matches.length > 0) {
      totalCount += matches.length;
      typesFound.add(pattern.name);
      result = result.replace(pattern.regex, pattern.replacement);
    }
  }

  return {
    redacted: result,
    redaction_count: totalCount,
    redacted_types: [...typesFound],
  };
}

/**
 * Recursively redact all string values in an object.
 *
 * Returns a deep copy with all string values redacted.
 */
export function redactInObject(
  obj: unknown,
  customPatterns?: PiiPattern[],
): unknown {
  if (typeof obj === "string") {
    return redactPII(obj, customPatterns).redacted;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => redactInObject(item, customPatterns));
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = redactInObject(value, customPatterns);
    }
    return result;
  }
  return obj;
}
