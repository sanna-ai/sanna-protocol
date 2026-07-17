/**
 * Loads reference/spec/ALGORITHM-v4-tables-v1.json (sha256-verified at
 * import) and exposes typed accessors. Tables are NEVER restated in code
 * here -- every value returned by this module is read out of the vendored
 * JSON artifact. See ALGORITHM-v4-c1c5-reference.md section 1.
 *
 * The hash constants below are integrity metadata for the vendored
 * artifacts (mandated by spec section 1: "verify the hash at build time"),
 * not a restatement of table content.
 *
 * Mirrors reference/tables.py one-for-one. Per the SAN-880/SAN-883
 * boundary this module -- like every other module in this package --
 * never invokes normalize(); tables are read as UTF-8 JSON text via
 * node:fs, independent of any field-text normalization concern.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

// Spec section 1 / draft-5.3 header: sha256 of ALGORITHM-v4-tables-v1.json.
export const TABLES_SHA256 =
  "0a18dd94bc811bb3166a4f8812e78f2b053a9f8f083b781a21fb0f8371f54ecc";
// sha256 of the vendored ALGORITHM-v4-c1c5-reference.md (draft 5.5, adds
// erratum e14 (spec sec 2.2 rule 4): LETTER_v1 classification pinned to
// UCD 15.0.0) -- the normative source this package implements; verified
// at import so a silently swapped spec cannot masquerade as the
// reviewed one.
export const ALGORITHM_SHA256 =
  "772a816b438527c1fadf1a4198ae5839a85f3b2ad82cbfefbaa86ff93e5034b6";

// Resolved cwd-independently from import.meta.url per SAN-880's package
// mechanics: from compiled dist/src/tables.js the spec artifacts live at
// ../../../spec/ (i.e. reference/spec/, three levels up from dist/src/).
const _SPEC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../spec");
const _TABLES_PATH = path.join(_SPEC_DIR, "ALGORITHM-v4-tables-v1.json");
const _ALGORITHM_PATH = path.join(_SPEC_DIR, "ALGORITHM-v4-c1c5-reference.md");

export class TablesIntegrityError extends Error {}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

interface StemRule {
  if_ends: string;
  min_len: number;
  replace_with: string;
  not_ends?: string;
  only_after?: string[];
}

interface ConditionOperatorRaw {
  tokens: string[];
  kind: string;
  polarity: string;
  force: string;
}

interface ComparatorIntervalTemplate {
  lo: string | null;
  lo_open: boolean;
  hi: string | null;
  hi_open: boolean;
}

interface ComparatorRaw {
  tokens: string[];
  interval: ComparatorIntervalTemplate;
}

interface FacetRaw {
  triggers: string[];
  deny_triggers: string[];
  valency: string[];
  measure: boolean;
  benefit: boolean;
  note?: string;
}

interface UnitRaw {
  group: string;
  factor: number;
}

/** Shape of the raw parsed JSON artifact -- mirrors the keys documented in
 * spec section 1 exactly (see reference/tables.py's constructor for the
 * matching Python field-by-field walk). */
export interface TablesRaw {
  tables_version: string;
  checks_version: number;
  notes: string;
  constants: Record<string, number>;
  ws_v1_codepoints: string[];
  stop_v1: string[];
  definitive_v1: string[];
  hedge_v1: string[];
  hedge_window_boundaries: string[];
  negators_v1: string[];
  negation_exceptions: [string, string][];
  quant_v1: { universal: string[]; existential: string[]; abstain: string[] };
  condition_operators_v1: ConditionOperatorRaw[];
  modal_abstain_v1: string[];
  adjunct_prepositions_v1: string[];
  relative_markers_v1: string[];
  excl_v1: [string, string][];
  complement_v1: [string, string][];
  units_v1: Record<string, UnitRaw>;
  currency_symbols_v1: Record<string, string>;
  facets_v1: Record<string, FacetRaw>;
  generic_benefit_triggers_v1: string[];
  facetproj_v1: Record<string, string>;
  stem_v1_rules: StemRule[];
  structural_punctuation: string[];
  sentence_terminators: string[];
  approx_v1: string[];
  contractions_v1: Record<string, string[]>;
  compound_head_v1: { rule: string };
  comparators_v1: ComparatorRaw[];
  concept_v1: Record<string, string>;
  participle_triggers_v1: string[];
}

function loadAndVerify(tablesPath: string): TablesRaw {
  const raw = readFileSync(tablesPath);
  const digest = sha256Hex(raw);
  if (digest !== TABLES_SHA256) {
    throw new TablesIntegrityError(
      `${tablesPath} sha256 mismatch: expected ${TABLES_SHA256}, got ${digest}`,
    );
  }
  const algoDigest = sha256Hex(readFileSync(_ALGORITHM_PATH));
  if (algoDigest !== ALGORITHM_SHA256) {
    throw new TablesIntegrityError(
      `${_ALGORITHM_PATH} sha256 mismatch: expected ${ALGORITHM_SHA256}, got ${algoDigest}`,
    );
  }
  return JSON.parse(raw.toString("utf-8")) as TablesRaw;
}

export class Tables {
  readonly raw: TablesRaw;

  // -- constants --
  readonly ENV_MAX_FIELD_BYTES: number;
  readonly ENV_MAX_SENTENCES: number;
  readonly ENV_MAX_FRAMES: number;
  readonly ENV_MAX_OBLIGATIONS: number;
  readonly ENV_MAX_EVIDENCE: number;
  readonly MAX_EXPR_NODES: number;
  readonly MAX_BOOL_ATOMS: number;
  readonly MAX_ENGINE_WORK: number;
  readonly MAX_ENGINE_BYTES: number;
  readonly L_MAX: number;
  readonly W_HEDGE: number;
  readonly NEG_WINDOW: number;
  readonly MAX_DEC_DIGITS: number;
  readonly MAX_DEC_SCALE: number;

  // -- WS_v1 code points: hex strings -> actual characters --
  readonly wsV1: ReadonlySet<string>;

  readonly stopV1: ReadonlySet<string>;
  readonly definitiveV1: readonly (readonly string[])[];
  readonly hedgeV1: readonly (readonly string[])[];
  readonly hedgeWindowBoundaries: ReadonlySet<string>;
  readonly negatorsV1: ReadonlySet<string>;
  readonly negationExceptions: ReadonlySet<string>; // canonical "a b" keys

  readonly quantUniversal: ReadonlySet<string>;
  readonly quantExistential: ReadonlySet<string>;
  readonly quantAbstain: ReadonlySet<string>;

  readonly conditionOperatorsV1: readonly {
    tokens: readonly string[];
    kind: string;
    polarity: string;
    force: string;
  }[];

  readonly modalAbstainV1: ReadonlySet<string>;
  readonly adjunctPrepositionsV1: ReadonlySet<string>;
  readonly relativeMarkersV1: ReadonlySet<string>;
  readonly exclV1: ReadonlySet<string>; // canonical unordered-pair keys
  readonly complementV1: readonly (readonly [string, string])[];
  readonly unitsV1: Readonly<Record<string, UnitRaw>>;
  readonly currencySymbolsV1: Readonly<Record<string, string>>;
  readonly facetsV1: Readonly<Record<string, FacetRaw>>;
  readonly genericBenefitTriggersV1: ReadonlySet<string>;
  readonly facetprojV1: Readonly<Record<string, string>>;
  readonly stemV1Rules: readonly StemRule[];
  readonly structuralPunctuation: ReadonlySet<string>;
  readonly sentenceTerminators: ReadonlySet<string>;
  readonly approxV1: ReadonlySet<string>;
  readonly contractionsV1: Readonly<Record<string, readonly string[]>>;
  readonly compoundHeadV1Rule: string;
  readonly comparatorsV1: readonly { tokens: readonly string[]; interval: ComparatorIntervalTemplate }[];
  readonly conceptV1: Readonly<Record<string, string>>;
  readonly participleTriggersV1: ReadonlySet<string>;

  constructor(data: TablesRaw) {
    this.raw = data;
    const c = data.constants;
    this.ENV_MAX_FIELD_BYTES = c.ENV_MAX_FIELD_BYTES;
    this.ENV_MAX_SENTENCES = c.ENV_MAX_SENTENCES;
    this.ENV_MAX_FRAMES = c.ENV_MAX_FRAMES;
    this.ENV_MAX_OBLIGATIONS = c.ENV_MAX_OBLIGATIONS;
    this.ENV_MAX_EVIDENCE = c.ENV_MAX_EVIDENCE;
    this.MAX_EXPR_NODES = c.MAX_EXPR_NODES;
    this.MAX_BOOL_ATOMS = c.MAX_BOOL_ATOMS;
    this.MAX_ENGINE_WORK = c.MAX_ENGINE_WORK;
    this.MAX_ENGINE_BYTES = c.MAX_ENGINE_BYTES;
    this.L_MAX = c.L_MAX;
    this.W_HEDGE = c.W_HEDGE;
    this.NEG_WINDOW = c.NEG_WINDOW;
    this.MAX_DEC_DIGITS = c.MAX_DEC_DIGITS;
    this.MAX_DEC_SCALE = c.MAX_DEC_SCALE;

    this.wsV1 = new Set(data.ws_v1_codepoints.map((h) => String.fromCodePoint(parseInt(h, 16))));

    this.stopV1 = new Set(data.stop_v1);
    this.definitiveV1 = data.definitive_v1.map((entry) => entry.split(" "));
    this.hedgeV1 = data.hedge_v1.map((entry) => entry.split(" "));
    this.hedgeWindowBoundaries = new Set(data.hedge_window_boundaries);
    this.negatorsV1 = new Set(data.negators_v1);
    this.negationExceptions = new Set(data.negation_exceptions.map(([a, b]) => `${a} ${b}`));

    this.quantUniversal = new Set(data.quant_v1.universal);
    this.quantExistential = new Set(data.quant_v1.existential);
    this.quantAbstain = new Set(data.quant_v1.abstain);

    this.conditionOperatorsV1 = data.condition_operators_v1.map((op) => ({
      tokens: op.tokens,
      kind: op.kind,
      polarity: op.polarity,
      force: op.force,
    }));

    this.modalAbstainV1 = new Set(data.modal_abstain_v1);
    this.adjunctPrepositionsV1 = new Set(data.adjunct_prepositions_v1);
    this.relativeMarkersV1 = new Set(data.relative_markers_v1);
    this.exclV1 = new Set(data.excl_v1.map(([a, b]) => (a < b ? `${a} ${b}` : `${b} ${a}`)));
    this.complementV1 = data.complement_v1.map(([a, b]) => [a, b] as const);
    // Null-prototype copies: JSON-parsed objects inherit Object.prototype,
    // so an input-derived bracket-lookup key like "constructor" would
    // otherwise resolve the inherited Object constructor instead of
    // missing as intended. Stripping the prototype makes every lookup on
    // these six tables miss cleanly (undefined) for such keys.
    this.unitsV1 = Object.assign(Object.create(null), data.units_v1);
    this.currencySymbolsV1 = Object.assign(Object.create(null), data.currency_symbols_v1);
    this.facetsV1 = Object.assign(Object.create(null), data.facets_v1);
    this.genericBenefitTriggersV1 = new Set(data.generic_benefit_triggers_v1);
    this.facetprojV1 = Object.assign(Object.create(null), data.facetproj_v1);
    this.stemV1Rules = data.stem_v1_rules;
    this.structuralPunctuation = new Set(data.structural_punctuation);
    this.sentenceTerminators = new Set(data.sentence_terminators);
    this.approxV1 = new Set(data.approx_v1);
    this.contractionsV1 = Object.assign(Object.create(null), data.contractions_v1);
    this.compoundHeadV1Rule = data.compound_head_v1.rule;
    this.comparatorsV1 = data.comparators_v1.map((entry) => ({
      tokens: entry.tokens,
      interval: entry.interval,
    }));
    this.conceptV1 = Object.assign(Object.create(null), data.concept_v1);
    this.participleTriggersV1 = new Set(data.participle_triggers_v1);
  }
}

function loadDefault(): Tables {
  return new Tables(loadAndVerify(_TABLES_PATH));
}

// Module-level singleton: import-time verification per spec section 1.
export const T: Tables = loadDefault();

/** Unordered-pair canonical key helper, shared by exclV1 membership tests
 * (relations.ts / extraction.ts) so both sides of an EXCL_v1 pair check
 * agree on ordering regardless of which term is `a` and which is `b`. */
export function unorderedPairKey(a: string, b: string): string {
  return a < b ? `${a} ${b}` : `${b} ${a}`;
}
