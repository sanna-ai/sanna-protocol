/**
 * Immutable structural-equality set utilities standing in for Python's
 * built-in `frozenset`. Python dataclasses (Extent, Bool atoms, ...) are
 * `frozen=True`, giving every `frozenset[str]` / `frozenset[tuple]` field
 * value-based equality and hashing for free (dict-key grouping, `<=`
 * subset tests, `|` union). TypeScript has no structural-equality
 * collection type, so every one of those operations is reimplemented here
 * against a canonical (deduplicated, order-independent) string key. The
 * canonical key format does not need to match any spec-normative byte
 * encoding (ATOMENC_v1, spec section 7, is documented but never invoked by
 * the Python reference implementation -- `_extent_identity_key` groups by
 * native Python tuple/frozenset structural equality, not by byte-encoding
 * Extents) -- it only needs to be injective and order-independent so two
 * structurally-equal sets always produce the same key and two
 * structurally-different sets never collide.
 */

/** A frozenset[str] equivalent: deduplicated, with a canonical key for use
 * as a Map key (grouping, complement/variable-identity lookups). */
export class FSet {
  private readonly items: readonly string[]; // deduplicated; order arbitrary but fixed
  private readonly keyStr: string;

  private constructor(items: readonly string[], keyStr: string) {
    this.items = items;
    this.keyStr = keyStr;
  }

  static readonly EMPTY: FSet = FSet.of([]);

  static of(iterable: Iterable<string>): FSet {
    const uniq = Array.from(new Set(iterable));
    // Canonical key: content-addressed, order-independent. Sorting by
    // plain JS string order is sufficient here (unlike output-affecting
    // sorts) because this key is used ONLY for internal equality/grouping
    // (Map keys) -- never serialized, never compared against a Python
    // ordering, and never determines evaluate() output (see module
    // docstring). A stable deterministic sort is all correctness requires.
    const sorted = uniq.slice().sort();
    return new FSet(sorted, JSON.stringify(sorted));
  }

  get size(): number {
    return this.items.length;
  }

  isEmpty(): boolean {
    return this.items.length === 0;
  }

  has(x: string): boolean {
    return this.items.includes(x);
  }

  isSubsetOf(other: FSet): boolean {
    return this.items.every((x) => other.has(x));
  }

  union(other: FSet): FSet {
    if (this.items.length === 0) return other;
    if (other.items.length === 0) return this;
    return FSet.of([...this.items, ...other.items]);
  }

  intersects(other: FSet): boolean {
    const [small, big] = this.items.length <= other.items.length ? [this, other] : [other, this];
    return small.items.some((x) => big.has(x));
  }

  intersection(other: FSet): FSet {
    return FSet.of(this.items.filter((x) => other.has(x)));
  }

  equals(other: FSet): boolean {
    return this.keyStr === other.keyStr;
  }

  toArray(): string[] {
    return this.items.slice();
  }

  /** Canonical, order-independent, injective string key for this set. */
  key(): string {
    return this.keyStr;
  }
}

/** A frozenset[(rel: str, objset: frozenset[str])] equivalent -- the
 * modifier-set shape used by Extent.modifiers (spec section 0: "modifiers:
 * frozenset[(rel: str, objset: frozenset[str])]"). */
export interface ModPair {
  readonly rel: string;
  readonly objset: FSet;
}

export class ModSet {
  private readonly pairs: readonly ModPair[];
  private readonly keyStr: string;

  private constructor(pairs: readonly ModPair[], keyStr: string) {
    this.pairs = pairs;
    this.keyStr = keyStr;
  }

  static readonly EMPTY: ModSet = ModSet.of([]);

  static of(iterable: Iterable<ModPair>): ModSet {
    const byKey = new Map<string, ModPair>();
    for (const p of iterable) {
      const k = JSON.stringify([p.rel, p.objset.toArray().slice().sort()]);
      if (!byKey.has(k)) byKey.set(k, p);
    }
    const keys = Array.from(byKey.keys()).sort();
    const pairs = keys.map((k) => byKey.get(k)!);
    return new ModSet(pairs, JSON.stringify(keys));
  }

  get size(): number {
    return this.pairs.length;
  }

  union(other: ModSet): ModSet {
    if (this.pairs.length === 0) return other;
    if (other.pairs.length === 0) return this;
    return ModSet.of([...this.pairs, ...other.pairs]);
  }

  [Symbol.iterator](): Iterator<ModPair> {
    return this.pairs[Symbol.iterator]();
  }

  toArray(): ModPair[] {
    return this.pairs.slice();
  }

  key(): string {
    return this.keyStr;
  }
}
