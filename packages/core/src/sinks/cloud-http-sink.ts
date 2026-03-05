/**
 * CloudHTTPSink — sends receipts to Cloud ingestion API via HTTPS POST.
 *
 * Uses native fetch() (Node 22+). Supports retry with exponential backoff,
 * batch delivery, and optional buffer-and-retry for resilience.
 */

import { readFileSync, appendFileSync, writeFileSync, existsSync } from "node:fs";
import { SPEC_VERSION } from "../receipt.js";
import type { Receipt, ReceiptSink, SinkResult, FailurePolicy } from "../types.js";

// ── Types ────────────────────────────────────────────────────────────

export interface CloudHTTPSinkOptions {
  apiUrl: string;
  apiKey: string;
  failurePolicy?: FailurePolicy;
  timeoutMs?: number;
  maxRetries?: number;
  retryBackoffBaseMs?: number;
  batchSize?: number;
  bufferPath?: string | null;
}

// ── No-retry status codes ────────────────────────────────────────────

const NO_RETRY_CODES = new Set([400, 401, 403]);

// ── CloudHTTPSink ────────────────────────────────────────────────────

export class CloudHTTPSink implements ReceiptSink {
  private _apiUrl: string;
  private _apiKey: string;
  private _failurePolicy: FailurePolicy;
  private _timeoutMs: number;
  private _maxRetries: number;
  private _retryBackoffBaseMs: number;
  private _batchSize: number;
  private _bufferPath: string | null;
  private _retryInterval: ReturnType<typeof setInterval> | null = null;
  private _closed = false;

  constructor(options: CloudHTTPSinkOptions) {
    this._apiUrl = options.apiUrl.replace(/\/$/, "");
    this._apiKey = options.apiKey;
    this._failurePolicy = options.failurePolicy ?? "log_and_continue";
    this._timeoutMs = options.timeoutMs ?? 10000;
    this._maxRetries = options.maxRetries ?? 3;
    this._retryBackoffBaseMs = options.retryBackoffBaseMs ?? 1000;
    this._batchSize = options.batchSize ?? 50;
    this._bufferPath = options.bufferPath ?? null;

    if (this._failurePolicy === "buffer_and_retry" && this._bufferPath) {
      this._startRetryLoop();
    }
  }

  async store(receipt: Receipt): Promise<SinkResult> {
    try {
      await this._sendWithRetry(`${this._apiUrl}/v1/receipts`, receipt);
      return { success: true, receiptId: receipt.receipt_id };
    } catch (err) {
      return this._handleFailure(receipt, err);
    }
  }

  async storeBatch(receipts: Receipt[]): Promise<SinkResult[]> {
    const results: SinkResult[] = [];

    for (let i = 0; i < receipts.length; i += this._batchSize) {
      const batch = receipts.slice(i, i + this._batchSize);
      try {
        await this._sendWithRetry(`${this._apiUrl}/v1/receipts/batch`, {
          receipts: batch,
        });
        for (const r of batch) {
          results.push({ success: true, receiptId: r.receipt_id });
        }
      } catch (err) {
        for (const r of batch) {
          results.push(this._handleFailure(r, err));
        }
      }
    }

    return results;
  }

  async flush(): Promise<void> {
    if (!this._bufferPath || !existsSync(this._bufferPath)) return;

    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      const lines = this._readBufferLines();
      if (lines.length === 0) return;

      const batch = lines.slice(0, this._batchSize);
      const receipts = batch.map((l) => JSON.parse(l) as Receipt);

      try {
        await this._sendWithRetry(`${this._apiUrl}/v1/receipts/batch`, {
          receipts,
        });
        // Remove sent lines from buffer
        const remaining = lines.slice(batch.length);
        writeFileSync(this._bufferPath, remaining.join("\n") + (remaining.length > 0 ? "\n" : ""));
      } catch {
        // Could not flush within deadline
        return;
      }
    }
  }

  async close(): Promise<void> {
    this._closed = true;
    if (this._retryInterval) {
      clearInterval(this._retryInterval);
      this._retryInterval = null;
    }
    await this.flush();
  }

  // ── Internal ─────────────────────────────────────────────────────

  private async _sendWithRetry(url: string, body: unknown): Promise<void> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this._maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = this._computeDelay(attempt);
        await new Promise((r) => setTimeout(r, delay));
      }

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this._timeoutMs);

        const response = await fetch(url, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this._apiKey}`,
            "Content-Type": "application/json",
            "User-Agent": `sanna-ts/${SPEC_VERSION}`,
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (response.status === 201) return;
        if (response.status === 409) return; // Duplicate = success

        if (NO_RETRY_CODES.has(response.status)) {
          throw new Error(
            `HTTP ${response.status}: ${await response.text().catch(() => "unknown")}`,
          );
        }

        if (response.status === 429) {
          const retryAfter = response.headers.get("Retry-After");
          if (retryAfter) {
            const seconds = parseInt(retryAfter, 10);
            if (!isNaN(seconds)) {
              await new Promise((r) => setTimeout(r, seconds * 1000));
            }
          }
          lastError = new Error(`HTTP 429: rate limited`);
          continue;
        }

        // 5xx or other — retry
        lastError = new Error(`HTTP ${response.status}`);
        continue;
      } catch (err) {
        if (err instanceof Error && NO_RETRY_CODES.has(parseInt(err.message.slice(5, 8)))) {
          throw err;
        }
        lastError = err instanceof Error ? err : new Error(String(err));
        continue;
      }
    }

    throw lastError ?? new Error("Max retries exceeded");
  }

  private _computeDelay(attempt: number): number {
    return this._retryBackoffBaseMs * Math.pow(2, attempt) + Math.random() * 500;
  }

  private _handleFailure(receipt: Receipt, err: unknown): SinkResult {
    const errorMsg = err instanceof Error ? err.message : String(err);

    if (this._failurePolicy === "buffer_and_retry" && this._bufferPath) {
      try {
        appendFileSync(this._bufferPath, JSON.stringify(receipt) + "\n");
      } catch {
        // Buffer write failed — last resort
      }
    }

    if (this._failurePolicy === "throw") {
      throw err instanceof Error ? err : new Error(errorMsg);
    }

    // log_and_continue or buffer_and_retry
    process.stderr.write(`[sanna] CloudHTTPSink error: ${errorMsg}\n`);
    return { success: false, error: errorMsg, receiptId: receipt.receipt_id };
  }

  private _readBufferLines(): string[] {
    if (!this._bufferPath || !existsSync(this._bufferPath)) return [];
    try {
      const content = readFileSync(this._bufferPath, "utf-8").trim();
      return content ? content.split("\n") : [];
    } catch {
      return [];
    }
  }

  private _startRetryLoop(): void {
    this._retryInterval = setInterval(async () => {
      if (this._closed) return;
      try {
        await this.flush();
      } catch {
        // Best-effort retry
      }
    }, 60_000);

    // Don't hold the process open
    if (this._retryInterval.unref) {
      this._retryInterval.unref();
    }
  }
}
