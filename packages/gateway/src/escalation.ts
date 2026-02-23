/**
 * Sanna Gateway — Escalation Store
 *
 * Manages pending escalations with HMAC token verification.
 * When a tool call requires escalation, an entry is created
 * with a cryptographic token that must be presented for approval.
 */

import { randomUUID, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { safeWriteJson } from "@sanna/core";

// ── Types ────────────────────────────────────────────────────────────

export type EscalationStatus = "pending" | "approved" | "denied" | "expired";

export interface Escalation {
  id: string;
  tool_name: string;
  args: Record<string, unknown>;
  reason: string;
  agent_id: string;
  status: EscalationStatus;
  token: string;
  created_at: string;
  expires_at: string;
  resolved_at?: string;
}

export interface CreateEscalationResult {
  escalation_id: string;
  token: string;
  expires_at: string;
}

export interface EscalationStoreOptions {
  storePath?: string;
  ttlSeconds?: number;
  hmacSecret: string;
}

// ── HMAC Token ───────────────────────────────────────────────────────

function generateToken(
  escalationId: string,
  toolName: string,
  createdAt: string,
  secret: string,
): string {
  const hmac = createHmac("sha256", secret);
  hmac.update(`${escalationId}:${toolName}:${createdAt}`);
  return hmac.digest("hex");
}

function verifyToken(
  token: string,
  escalationId: string,
  toolName: string,
  createdAt: string,
  secret: string,
): boolean {
  const expected = generateToken(escalationId, toolName, createdAt, secret);
  if (token.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

// ── Escalation Store ─────────────────────────────────────────────────

export class EscalationStore {
  private _escalations = new Map<string, Escalation>();
  private _storePath: string | undefined;
  private _ttlSeconds: number;
  private _hmacSecret: string;

  constructor(options: EscalationStoreOptions) {
    this._storePath = options.storePath;
    this._ttlSeconds = options.ttlSeconds ?? 300;
    this._hmacSecret = options.hmacSecret;

    // Load from disk if path given
    if (this._storePath && existsSync(this._storePath)) {
      try {
        const data = JSON.parse(readFileSync(this._storePath, "utf-8"));
        if (Array.isArray(data)) {
          for (const esc of data) {
            this._escalations.set(esc.id, esc);
          }
        }
      } catch {
        // Corrupted file — start fresh
      }
    }
  }

  /**
   * Create a new pending escalation.
   */
  createEscalation(
    toolName: string,
    args: Record<string, unknown>,
    reason: string,
    agentId: string,
  ): CreateEscalationResult {
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(
      Date.now() + this._ttlSeconds * 1000,
    ).toISOString();
    const token = generateToken(id, toolName, createdAt, this._hmacSecret);

    const escalation: Escalation = {
      id,
      tool_name: toolName,
      args,
      reason,
      agent_id: agentId,
      status: "pending",
      token,
      created_at: createdAt,
      expires_at: expiresAt,
    };

    this._escalations.set(id, escalation);
    this._persist();

    return { escalation_id: id, token, expires_at: expiresAt };
  }

  /**
   * Verify HMAC token and approve an escalation.
   */
  verifyAndApprove(escalationId: string, token: string): boolean {
    const esc = this._escalations.get(escalationId);
    if (!esc) return false;
    if (esc.status !== "pending") return false;

    // Check expiry
    if (new Date(esc.expires_at).getTime() <= Date.now()) {
      esc.status = "expired";
      this._persist();
      return false;
    }

    // Verify HMAC
    if (
      !verifyToken(
        token,
        esc.id,
        esc.tool_name,
        esc.created_at,
        this._hmacSecret,
      )
    ) {
      return false;
    }

    esc.status = "approved";
    esc.resolved_at = new Date().toISOString();
    this._persist();
    return true;
  }

  /**
   * Verify HMAC token and deny an escalation.
   */
  verifyAndDeny(escalationId: string, token: string): boolean {
    const esc = this._escalations.get(escalationId);
    if (!esc) return false;
    if (esc.status !== "pending") return false;

    // Check expiry
    if (new Date(esc.expires_at).getTime() <= Date.now()) {
      esc.status = "expired";
      this._persist();
      return false;
    }

    // Verify HMAC
    if (
      !verifyToken(
        token,
        esc.id,
        esc.tool_name,
        esc.created_at,
        this._hmacSecret,
      )
    ) {
      return false;
    }

    esc.status = "denied";
    esc.resolved_at = new Date().toISOString();
    this._persist();
    return true;
  }

  /**
   * Get the status of an escalation.
   */
  getStatus(escalationId: string): EscalationStatus | null {
    const esc = this._escalations.get(escalationId);
    if (!esc) return null;

    // Check for expiry
    if (
      esc.status === "pending" &&
      new Date(esc.expires_at).getTime() <= Date.now()
    ) {
      esc.status = "expired";
      this._persist();
    }

    return esc.status;
  }

  /**
   * Get full escalation details.
   */
  get(escalationId: string): Escalation | undefined {
    return this._escalations.get(escalationId);
  }

  /**
   * Purge expired escalations.
   */
  cleanup(): number {
    let count = 0;
    const now = Date.now();
    for (const [id, esc] of this._escalations) {
      if (new Date(esc.expires_at).getTime() < now) {
        if (esc.status === "pending") {
          esc.status = "expired";
        }
        // Remove resolved or expired entries that are older than 2x TTL
        const age = now - new Date(esc.created_at).getTime();
        if (age > this._ttlSeconds * 2000) {
          this._escalations.delete(id);
          count++;
        }
      }
    }
    if (count > 0) this._persist();
    return count;
  }

  get size(): number {
    return this._escalations.size;
  }

  private _persist(): void {
    if (!this._storePath) return;
    try {
      safeWriteJson(this._storePath, [...this._escalations.values()]);
    } catch {
      // Best-effort persistence
    }
  }
}
