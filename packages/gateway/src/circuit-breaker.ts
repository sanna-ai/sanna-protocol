/**
 * Sanna Gateway — Circuit Breaker
 *
 * Per-downstream circuit breaker with three states:
 * CLOSED (normal), OPEN (failing), HALF_OPEN (probing).
 */

// ── Types ────────────────────────────────────────────────────────────

export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerOptions {
  failureThreshold: number;
  recoveryTimeoutMs: number;
  halfOpenMax: number;
}

export type StateChangeCallback = (
  from: CircuitState,
  to: CircuitState,
) => void;

// ── Circuit Breaker ──────────────────────────────────────────────────

export class CircuitBreakerOpenError extends Error {
  constructor(message?: string) {
    super(message ?? "Circuit breaker is OPEN — call rejected");
    this.name = "CircuitBreakerOpenError";
  }
}

export class CircuitBreaker {
  private _state: CircuitState = "closed";
  private _failureCount = 0;
  private _halfOpenAttempts = 0;
  private _lastFailureTime = 0;
  private _listeners: StateChangeCallback[] = [];

  private readonly _failureThreshold: number;
  private readonly _recoveryTimeoutMs: number;
  private readonly _halfOpenMax: number;

  constructor(options: CircuitBreakerOptions) {
    this._failureThreshold = options.failureThreshold;
    this._recoveryTimeoutMs = options.recoveryTimeoutMs;
    this._halfOpenMax = options.halfOpenMax;
  }

  /**
   * Execute a function through the circuit breaker.
   *
   * - CLOSED: execute fn, track failures, open if threshold hit
   * - OPEN: reject immediately; if recovery timeout elapsed, transition to HALF_OPEN
   * - HALF_OPEN: allow up to halfOpenMax probes; success → CLOSED, failure → OPEN
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this._state === "open") {
      // Check if recovery timeout has elapsed
      const elapsed = Date.now() - this._lastFailureTime;
      if (elapsed >= this._recoveryTimeoutMs) {
        this._transition("half_open");
      } else {
        throw new CircuitBreakerOpenError();
      }
    }

    if (this._state === "half_open") {
      if (this._halfOpenAttempts >= this._halfOpenMax) {
        throw new CircuitBreakerOpenError(
          "Circuit breaker is HALF_OPEN — max probes reached",
        );
      }
      this._halfOpenAttempts++;
    }

    try {
      const result = await fn();
      this._onSuccess();
      return result;
    } catch (err) {
      this._onFailure();
      throw err;
    }
  }

  getState(): CircuitState {
    return this._state;
  }

  reset(): void {
    this._failureCount = 0;
    this._halfOpenAttempts = 0;
    this._lastFailureTime = 0;
    this._transition("closed");
  }

  onStateChange(callback: StateChangeCallback): void {
    this._listeners.push(callback);
  }

  private _onSuccess(): void {
    if (this._state === "half_open") {
      // Successful probe — recover to closed
      this._failureCount = 0;
      this._halfOpenAttempts = 0;
      this._transition("closed");
    } else if (this._state === "closed") {
      // Reset failure count on success
      this._failureCount = 0;
    }
  }

  private _onFailure(): void {
    this._lastFailureTime = Date.now();

    if (this._state === "half_open") {
      // Failed probe — back to open
      this._halfOpenAttempts = 0;
      this._transition("open");
    } else if (this._state === "closed") {
      this._failureCount++;
      if (this._failureCount >= this._failureThreshold) {
        this._transition("open");
      }
    }
  }

  private _transition(to: CircuitState): void {
    if (this._state === to) return;
    const from = this._state;
    this._state = to;
    for (const listener of this._listeners) {
      try {
        listener(from, to);
      } catch {
        // Don't let listener errors break the circuit breaker
      }
    }
  }
}
