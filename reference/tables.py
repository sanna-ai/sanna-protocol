"""Loads reference/spec/ALGORITHM-v4-tables-v1.json (sha256-verified at
import) and exposes typed accessors. Tables are NEVER restated in code
here -- every value returned by this module is read out of the vendored
JSON artifact. See ALGORITHM-v4-c1c5-reference.md section 1.

The single hash constant below is integrity metadata for the vendored
artifact (mandated by spec section 1: "verify the hash at build time"),
not a restatement of table content.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# Spec section 1 / draft-5.1 header: sha256 of ALGORITHM-v4-tables-v1.json.
TABLES_SHA256 = "6035c1b22969f84db43c444fefd53a7998b5d2114621a05fc566d87a8a335b71"

_SPEC_DIR = Path(__file__).parent / "spec"
_TABLES_PATH = _SPEC_DIR / "ALGORITHM-v4-tables-v1.json"


class TablesIntegrityError(RuntimeError):
    """Raised when the vendored tables artifact does not match TABLES_SHA256."""


def _load_and_verify(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != TABLES_SHA256:
        raise TablesIntegrityError(
            f"{path} sha256 mismatch: expected {TABLES_SHA256}, got {digest}"
        )
    return json.loads(raw.decode("utf-8"))


class Tables:
    """Typed accessors over the loaded tables JSON. One instance per process
    (see the module-level singleton `T` below); consumers should never
    mutate the returned collections.
    """

    def __init__(self, data: dict[str, Any]):
        self._data = data

        # -- constants (section: "constants") --
        c = data["constants"]
        self.ENV_MAX_FIELD_BYTES: int = c["ENV_MAX_FIELD_BYTES"]
        self.ENV_MAX_SENTENCES: int = c["ENV_MAX_SENTENCES"]
        self.ENV_MAX_FRAMES: int = c["ENV_MAX_FRAMES"]
        self.ENV_MAX_OBLIGATIONS: int = c["ENV_MAX_OBLIGATIONS"]
        self.ENV_MAX_EVIDENCE: int = c["ENV_MAX_EVIDENCE"]
        self.MAX_EXPR_NODES: int = c["MAX_EXPR_NODES"]
        self.MAX_BOOL_ATOMS: int = c["MAX_BOOL_ATOMS"]
        self.MAX_ENGINE_WORK: int = c["MAX_ENGINE_WORK"]
        self.MAX_ENGINE_BYTES: int = c["MAX_ENGINE_BYTES"]
        self.L_MAX: int = c["L_MAX"]
        self.W_HEDGE: int = c["W_HEDGE"]
        self.NEG_WINDOW: int = c["NEG_WINDOW"]
        self.MAX_DEC_DIGITS: int = c["MAX_DEC_DIGITS"]
        self.MAX_DEC_SCALE: int = c["MAX_DEC_SCALE"]

        # -- WS_v1 code points: hex strings -> actual characters --
        self.ws_v1: frozenset[str] = frozenset(
            chr(int(h, 16)) for h in data["ws_v1_codepoints"]
        )

        self.stop_v1: frozenset[str] = frozenset(data["stop_v1"])
        self.definitive_v1: tuple[tuple[str, ...], ...] = tuple(
            tuple(entry.split(" ")) for entry in data["definitive_v1"]
        )
        self.hedge_v1: tuple[tuple[str, ...], ...] = tuple(
            tuple(entry.split(" ")) for entry in data["hedge_v1"]
        )
        self.hedge_window_boundaries: frozenset[str] = frozenset(
            data["hedge_window_boundaries"]
        )
        self.negators_v1: frozenset[str] = frozenset(data["negators_v1"])
        self.negation_exceptions: frozenset[tuple[str, str]] = frozenset(
            tuple(pair) for pair in data["negation_exceptions"]
        )

        q = data["quant_v1"]
        self.quant_universal: frozenset[str] = frozenset(q["universal"])
        self.quant_existential: frozenset[str] = frozenset(q["existential"])
        self.quant_abstain: frozenset[str] = frozenset(q["abstain"])

        self.condition_operators_v1: tuple[dict[str, Any], ...] = tuple(
            {
                "tokens": tuple(op["tokens"]),
                "kind": op["kind"],
                "polarity": op["polarity"],
                "force": op["force"],
            }
            for op in data["condition_operators_v1"]
        )

        self.modal_abstain_v1: frozenset[str] = frozenset(data["modal_abstain_v1"])
        self.adjunct_prepositions_v1: frozenset[str] = frozenset(
            data["adjunct_prepositions_v1"]
        )
        self.relative_markers_v1: frozenset[str] = frozenset(
            data["relative_markers_v1"]
        )
        self.excl_v1: frozenset[frozenset[str]] = frozenset(
            frozenset(pair) for pair in data["excl_v1"]
        )
        self.complement_v1: tuple[tuple[str, str], ...] = tuple(
            tuple(pair) for pair in data["complement_v1"]
        )
        self.units_v1: dict[str, dict[str, Any]] = dict(data["units_v1"])
        self.currency_symbols_v1: dict[str, str] = dict(data["currency_symbols_v1"])
        self.facets_v1: dict[str, dict[str, Any]] = dict(data["facets_v1"])
        self.generic_benefit_triggers_v1: frozenset[str] = frozenset(
            data["generic_benefit_triggers_v1"]
        )
        self.facetproj_v1: dict[str, str] = dict(data["facetproj_v1"])
        self.stem_v1_rules: tuple[dict[str, Any], ...] = tuple(
            data["stem_v1_rules"]
        )
        self.structural_punctuation: frozenset[str] = frozenset(
            data["structural_punctuation"]
        )
        self.sentence_terminators: frozenset[str] = frozenset(
            data["sentence_terminators"]
        )
        self.approx_v1: frozenset[str] = frozenset(data["approx_v1"])
        self.contractions_v1: dict[str, tuple[str, ...]] = {
            k: tuple(v) for k, v in data["contractions_v1"].items()
        }
        self.compound_head_v1_rule: str = data["compound_head_v1"]["rule"]
        self.comparators_v1: tuple[dict[str, Any], ...] = tuple(
            {"tokens": tuple(entry["tokens"]), "interval": dict(entry["interval"])}
            for entry in data["comparators_v1"]
        )
        self.concept_v1: dict[str, str] = dict(data["concept_v1"])

        # trigger / deny_trigger union index, built once here since
        # trigger_scan (3.1) requires "one pass over the union of all
        # facets' triggers + deny_triggers as folded token sequences".
        # Table entries are single words in this artifact, but the loader
        # treats them as folded token sequences per spec section 1 so a
        # future multi-word trigger addition needs no code change.
        triggers: dict[tuple[str, ...], list[tuple[str, bool]]] = {}
        for facet_name, facet in self.facets_v1.items():
            for trig in facet["triggers"]:
                key = tuple(trig.split(" "))
                triggers.setdefault(key, []).append((facet_name, False))
            for trig in facet["deny_triggers"]:
                key = tuple(trig.split(" "))
                triggers.setdefault(key, []).append((facet_name, True))
        self._trigger_index: dict[tuple[str, ...], list[tuple[str, bool]]] = triggers

    @property
    def raw(self) -> dict[str, Any]:
        return self._data


def _load_default() -> Tables:
    return Tables(_load_and_verify(_TABLES_PATH))


# Module-level singleton: import-time verification per spec section 1.
T: Tables = _load_default()
