/**
 * CompositeSink — fan-out receipts to multiple sinks.
 *
 * Failure isolation: one sink failing does not prevent others.
 * Errors are aggregated in the result.
 */

import type { Receipt, ReceiptSink, SinkResult } from "../types.js";

export class CompositeSink implements ReceiptSink {
  private _sinks: ReceiptSink[];

  constructor(sinks: ReceiptSink[]) {
    this._sinks = sinks;
  }

  async store(receipt: Receipt): Promise<SinkResult> {
    const results = await Promise.allSettled(
      this._sinks.map((s) => s.store(receipt)),
    );

    const errors: string[] = [];
    for (const r of results) {
      if (r.status === "rejected") {
        errors.push(r.reason instanceof Error ? r.reason.message : String(r.reason));
      } else if (!r.value.success && r.value.error) {
        errors.push(r.value.error);
      }
    }

    if (errors.length > 0) {
      return {
        success: false,
        error: errors.join("; "),
        receiptId: receipt.receipt_id,
      };
    }

    return { success: true, receiptId: receipt.receipt_id };
  }

  async storeBatch(receipts: Receipt[]): Promise<SinkResult[]> {
    // Delegate to each sink's storeBatch or fall back to individual store
    const allResults = await Promise.allSettled(
      this._sinks.map(async (s) => {
        if (s.storeBatch) {
          return s.storeBatch(receipts);
        }
        return Promise.all(receipts.map((r) => s.store(r)));
      }),
    );

    // Aggregate per-receipt results across sinks
    const aggregated: SinkResult[] = receipts.map((r) => ({
      success: true,
      receiptId: r.receipt_id,
    }));

    for (const settled of allResults) {
      if (settled.status === "rejected") {
        const errMsg = settled.reason instanceof Error
          ? settled.reason.message
          : String(settled.reason);
        for (const agg of aggregated) {
          agg.success = false;
          agg.error = agg.error ? `${agg.error}; ${errMsg}` : errMsg;
        }
      } else {
        for (let i = 0; i < settled.value.length; i++) {
          const sinkResult = settled.value[i];
          if (!sinkResult.success) {
            aggregated[i].success = false;
            aggregated[i].error = aggregated[i].error
              ? `${aggregated[i].error}; ${sinkResult.error}`
              : sinkResult.error;
          }
        }
      }
    }

    return aggregated;
  }

  async flush(): Promise<void> {
    await Promise.allSettled(
      this._sinks.map((s) => s.flush?.()),
    );
  }

  async close(): Promise<void> {
    await Promise.allSettled(
      this._sinks.map((s) => s.close?.()),
    );
  }
}
