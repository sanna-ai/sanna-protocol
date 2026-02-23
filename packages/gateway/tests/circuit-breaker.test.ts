import { describe, it, expect } from "vitest";
import {
  CircuitBreaker,
  CircuitBreakerOpenError,
} from "../src/circuit-breaker.js";
import type { CircuitState } from "../src/circuit-breaker.js";

function makeBreaker(
  threshold = 3,
  recoveryMs = 100,
  halfOpenMax = 1,
) {
  return new CircuitBreaker({
    failureThreshold: threshold,
    recoveryTimeoutMs: recoveryMs,
    halfOpenMax,
  });
}

describe("CircuitBreaker", () => {
  it("should start in CLOSED state", () => {
    const cb = makeBreaker();
    expect(cb.getState()).toBe("closed");
  });

  it("should execute successfully in CLOSED state", async () => {
    const cb = makeBreaker();
    const result = await cb.execute(() => Promise.resolve("ok"));
    expect(result).toBe("ok");
    expect(cb.getState()).toBe("closed");
  });

  it("should stay CLOSED on failures below threshold", async () => {
    const cb = makeBreaker(3);
    for (let i = 0; i < 2; i++) {
      await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }
    expect(cb.getState()).toBe("closed");
  });

  it("should transition to OPEN when failure threshold reached", async () => {
    const cb = makeBreaker(3);
    for (let i = 0; i < 3; i++) {
      await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }
    expect(cb.getState()).toBe("open");
  });

  it("should reject calls in OPEN state", async () => {
    const cb = makeBreaker(1, 10_000);
    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    expect(cb.getState()).toBe("open");

    await expect(
      cb.execute(() => Promise.resolve("should not run")),
    ).rejects.toThrow(CircuitBreakerOpenError);
  });

  it("should transition to HALF_OPEN after recovery timeout", async () => {
    const cb = makeBreaker(1, 50);
    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    expect(cb.getState()).toBe("open");

    // Wait for recovery timeout
    await new Promise((r) => setTimeout(r, 60));

    // Next call should transition to HALF_OPEN and execute
    const result = await cb.execute(() => Promise.resolve("recovered"));
    expect(result).toBe("recovered");
    expect(cb.getState()).toBe("closed"); // Successful probe → closed
  });

  it("should return to OPEN on failed probe in HALF_OPEN", async () => {
    const cb = makeBreaker(1, 50);
    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    // Wait for recovery
    await new Promise((r) => setTimeout(r, 60));

    // Failed probe
    await cb
      .execute(() => Promise.reject(new Error("still failing")))
      .catch(() => {});
    expect(cb.getState()).toBe("open");
  });

  it("should recover from HALF_OPEN to CLOSED on success", async () => {
    const cb = makeBreaker(1, 50);
    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    await new Promise((r) => setTimeout(r, 60));

    await cb.execute(() => Promise.resolve("success"));
    expect(cb.getState()).toBe("closed");
  });

  it("should limit HALF_OPEN probes to halfOpenMax", async () => {
    const cb = makeBreaker(1, 50, 1);
    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    await new Promise((r) => setTimeout(r, 60));

    // First probe — should be allowed
    const p1 = cb.execute(
      () => new Promise((resolve) => setTimeout(() => resolve("slow"), 200)),
    );

    // Second probe — should be rejected (max reached)
    await expect(
      cb.execute(() => Promise.resolve("should not run")),
    ).rejects.toThrow(CircuitBreakerOpenError);

    await p1;
  });

  it("should reset to CLOSED", async () => {
    const cb = makeBreaker(1, 10_000);
    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    expect(cb.getState()).toBe("open");

    cb.reset();
    expect(cb.getState()).toBe("closed");

    const result = await cb.execute(() => Promise.resolve("ok"));
    expect(result).toBe("ok");
  });

  it("should emit state change events", async () => {
    const cb = makeBreaker(1, 50);
    const changes: Array<{ from: CircuitState; to: CircuitState }> = [];
    cb.onStateChange((from, to) => changes.push({ from, to }));

    await cb.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    expect(changes).toEqual([{ from: "closed", to: "open" }]);

    await new Promise((r) => setTimeout(r, 60));
    await cb.execute(() => Promise.resolve("ok"));
    expect(changes).toHaveLength(3); // open→half_open, half_open→closed
  });

  it("should reset failure count on success in CLOSED state", async () => {
    const cb = makeBreaker(3);
    // 2 failures
    await cb.execute(() => Promise.reject(new Error("f"))).catch(() => {});
    await cb.execute(() => Promise.reject(new Error("f"))).catch(() => {});
    // 1 success resets
    await cb.execute(() => Promise.resolve("ok"));
    // 2 more failures — should still be closed (threshold is 3)
    await cb.execute(() => Promise.reject(new Error("f"))).catch(() => {});
    await cb.execute(() => Promise.reject(new Error("f"))).catch(() => {});
    expect(cb.getState()).toBe("closed");
  });

  it("should propagate errors from fn", async () => {
    const cb = makeBreaker();
    await expect(
      cb.execute(() => Promise.reject(new Error("custom error"))),
    ).rejects.toThrow("custom error");
  });
});
