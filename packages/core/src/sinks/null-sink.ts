/**
 * NullSink — discards all receipts. Useful for testing.
 */

import type { Receipt, ReceiptSink, SinkResult } from "../types.js";

export class NullSink implements ReceiptSink {
  async store(receipt: Receipt): Promise<SinkResult> {
    return { success: true, receiptId: receipt.receipt_id };
  }

  async storeBatch(receipts: Receipt[]): Promise<SinkResult[]> {
    return receipts.map((r) => ({ success: true, receiptId: r.receipt_id }));
  }

  async flush(): Promise<void> {}
  async close(): Promise<void> {}
}
