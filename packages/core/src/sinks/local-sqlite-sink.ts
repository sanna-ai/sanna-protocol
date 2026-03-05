/**
 * LocalSQLiteSink — persists receipts to a local SQLite database.
 * Wraps ReceiptStore as a ReceiptSink interface.
 */

import { ReceiptStore } from "../store.js";
import type { Receipt, ReceiptSink, SinkResult } from "../types.js";

export class LocalSQLiteSink implements ReceiptSink {
  private _store: ReceiptStore;

  constructor(dbPath: string) {
    this._store = new ReceiptStore(dbPath);
  }

  async store(receipt: Receipt): Promise<SinkResult> {
    try {
      this._store.save(receipt);
      return { success: true, receiptId: receipt.receipt_id };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
        receiptId: receipt.receipt_id,
      };
    }
  }

  async storeBatch(receipts: Receipt[]): Promise<SinkResult[]> {
    return Promise.all(receipts.map((r) => this.store(r)));
  }

  async flush(): Promise<void> {}

  async close(): Promise<void> {
    this._store.close();
  }

  getStore(): ReceiptStore {
    return this._store;
  }
}
