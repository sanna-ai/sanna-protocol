#!/usr/bin/env python3
"""Generate fixtures/constitution-signable-vectors-v2.json (SAN-492).

The v2 unified canonical signable form. Generator IS the reference
implementation; SDKs (sanna-repo + sanna-ts) MUST produce byte-identical
output when they implement signing_version=2.

Note: this generator uses Python SDK helpers (parse_constitution,
compute_constitution_hash, _identity_dict, _reasoning_config_to_dict).
The byte-equal contract is the resulting vectors file, not the helper
implementation. SDKs match bytes; the helpers' semantics are the v2
form's reference. Future incompatible canonical-form changes MUST bump
signing_version to v3 rather than mutating v2.

Usage: python3 tools/generate_signable_vectors_v2.py
"""

import hashlib
import json
import sys
from pathlib import Path

from sanna.constitution import (
    _identity_dict,
    _reasoning_config_to_dict,
    compute_constitution_hash,
    parse_constitution,
)
from sanna.hashing import canonical_json_bytes

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
VECTORS_PATH = FIXTURES / "constitution-signable-vectors-v2.json"

FIXED_APPROVAL_DATE = "2026-05-07"


# -- v2 canonical form construction (THE REFERENCE) --

def build_v2_signable_dict(constitution_dict: dict) -> dict:
    """Build the v2 canonical signable dict from a Constitution dict.

    See spec Section 5.3 for the normative form definition. This
    function is the reference implementation; SDKs match bytes.
    """
    from dataclasses import asdict

    c = parse_constitution(constitution_dict)
    identity_d = _identity_dict(c.identity)

    prov_d = {
        "authored_by": c.provenance.authored_by,
        "approved_by": c.provenance.approved_by,
        "approval_date": c.provenance.approval_date,
        "approval_method": c.provenance.approval_method,
        "change_history": c.provenance.change_history,
    }
    if c.provenance.signature is not None:
        prov_d["signature"] = {
            "value": "",
            "key_id": c.provenance.signature.key_id,
            "signed_by": c.provenance.signature.signed_by,
            "signed_at": c.provenance.signature.signed_at,
            "scheme": c.provenance.signature.scheme,
        }
    else:
        prov_d["signature"] = None

    result = {
        "schema_version": c.schema_version,
        "identity": identity_d,
        "provenance": prov_d,
        "boundaries": [asdict(b) for b in c.boundaries],
        "trust_tiers": asdict(c.trust_tiers),
        "halt_conditions": [asdict(h) for h in c.halt_conditions],
        "invariants": [asdict(inv) for inv in c.invariants],
        "policy_hash": c.policy_hash,
    }

    if c.authority_boundaries is not None:
        ab = c.authority_boundaries
        ab_d = {
            "cannot_execute": ab.cannot_execute,
            "must_escalate": [
                {
                    "condition": r.condition,
                    "target": (
                        None if r.target is None
                        else {
                            "type": r.target.type,
                            "url": r.target.url,
                            "handler": r.target.handler,
                        }
                    ),
                }
                for r in ab.must_escalate
            ],
            "can_execute": ab.can_execute,
            "default_escalation": ab.default_escalation,
        }
        if ab.escalation_visibility != "visible":
            ab_d["escalation_visibility"] = ab.escalation_visibility
        if ab.anomaly_tracking.cli or ab.anomaly_tracking.http:
            at = {}
            if ab.anomaly_tracking.cli:
                at["cli"] = True
            if ab.anomaly_tracking.http:
                at["http"] = True
            ab_d["anomaly_tracking"] = at
        result["authority_boundaries"] = ab_d
        result["escalation_targets"] = {"default": ab.default_escalation}

    if c.composition is not None:
        result["composition"] = {"escalation_visibility": c.composition.escalation_visibility}

    if c.cli_permissions is not None:
        cp = c.cli_permissions
        result["cli_permissions"] = {
            "mode": cp.mode,
            "justification_required": cp.justification_required,
            "inspect_scripts": cp.inspect_scripts,
            "commands": [
                {
                    "id": cmd.id,
                    "binary": cmd.binary,
                    "authority": cmd.authority,
                    "argv_pattern": cmd.argv_pattern,
                    "description": cmd.description,
                    "escalation_target": cmd.escalation_target,
                }
                for cmd in cp.commands
            ],
            "invariants": [
                {
                    "id": inv.id,
                    "description": inv.description,
                    "verdict": inv.verdict,
                    "pattern": inv.pattern,
                    "condition": inv.condition,
                }
                for inv in cp.invariants
            ],
        }

    if c.api_permissions is not None:
        ap = c.api_permissions
        result["api_permissions"] = {
            "mode": ap.mode,
            "justification_required": ap.justification_required,
            "endpoints": [
                {
                    "id": ep.id,
                    "url_pattern": ep.url_pattern,
                    "authority": ep.authority,
                    "methods": ep.methods,
                    "description": ep.description,
                    "escalation_target": ep.escalation_target,
                }
                for ep in ap.endpoints
            ],
            "invariants": [
                {
                    "id": inv.id,
                    "description": inv.description,
                    "verdict": inv.verdict,
                    "pattern": inv.pattern,
                }
                for inv in ap.invariants
            ],
        }

    if c.trusted_sources is not None:
        result["trusted_sources"] = asdict(c.trusted_sources)

    if c.version != "1.0":
        result["version"] = c.version

    if c.reasoning is not None:
        result["reasoning"] = _reasoning_config_to_dict(c.reasoning, for_signing=True)

    return result


# -- Vector input factories --

def _base() -> dict:
    """Minimal valid constitution at sanna_constitution 1.1.0 with v2 signature."""
    return {
        "sanna_constitution": "1.1.0",
        "identity": {
            "agent_name": "san-492-v2-vector-agent",
            "domain": "testing",
            "description": "v2 cross-SDK vector",
        },
        "provenance": {
            "authored_by": "test-author@sanna.dev",
            "approved_by": ["test-author@sanna.dev"],
            "approval_date": FIXED_APPROVAL_DATE,
            "approval_method": "vector-generation",
            "change_history": [],
            "signature": {
                "value": "",
                "key_id": None,
                "signed_by": "",
                "signed_at": "",
                "scheme": "constitution_sig_v2",
            },
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Vector test boundary",
                "category": "scope",
                "severity": "medium",
            },
        ],
        "trust_tiers": {"autonomous": [], "requires_approval": [], "prohibited": []},
        "halt_conditions": [],
        "invariants": [],
    }


def _base_with_authority() -> dict:
    c = _base()
    c["authority_boundaries"] = {
        "cannot_execute": [],
        "must_escalate": [],
        "can_execute": [],
    }
    c["escalation_targets"] = {"default": "log"}
    return c


# -- must_escalate.target shapes (5 vectors, SAN-490 shapes under v2) --

def _v2_target_no_optionals() -> dict:
    c = _base_with_authority()
    c["authority_boundaries"]["must_escalate"] = [
        {"condition": "target with no optional fields", "target": {"type": "log"}},
    ]
    return c


def _v2_target_url_only() -> dict:
    c = _base_with_authority()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target with url only",
            "target": {"type": "webhook", "url": "https://example.com/escalations"},
        },
    ]
    return c


def _v2_target_handler_only() -> dict:
    c = _base_with_authority()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target with handler only",
            "target": {"type": "callback", "handler": "review_handler"},
        },
    ]
    return c


def _v2_target_null() -> dict:
    c = _base_with_authority()
    c["authority_boundaries"]["must_escalate"] = [
        {"condition": "target=null", "target": None},
    ]
    return c


def _v2_target_all_fields() -> dict:
    c = _base_with_authority()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target with all fields",
            "target": {
                "type": "webhook",
                "url": "https://example.com/escalations",
                "handler": "review_handler",
            },
        },
    ]
    return c


# -- cli_permissions shapes (5 vectors) --

def _v2_cli_empty() -> dict:
    c = _base()
    c["cli_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "commands": [],
        "invariants": [],
    }
    return c


def _v2_cli_min_fields() -> dict:
    c = _base()
    c["cli_permissions"] = {
        "commands": [
            {"id": "cli-001", "binary": "git", "authority": "can_execute"},
        ],
    }
    return c


def _v2_cli_all_fields() -> dict:
    c = _base()
    c["cli_permissions"] = {
        "mode": "permissive",
        "justification_required": False,
        "commands": [
            {
                "id": "cli-001",
                "binary": "git",
                "authority": "can_execute",
                "argv_pattern": "commit *",
                "description": "Allow git commit",
                "escalation_target": None,
            },
        ],
        "invariants": [],
    }
    return c


def _v2_cli_inspect_scripts() -> dict:
    c = _base()
    c["cli_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "inspect_scripts": True,
        "commands": [
            {"id": "cli-001", "binary": "bash", "authority": "must_escalate"},
        ],
        "invariants": [],
    }
    return c


def _v2_cli_with_invariants() -> dict:
    c = _base()
    c["cli_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "commands": [],
        "invariants": [
            {
                "id": "cli-inv-001",
                "description": "No rm -rf",
                "verdict": "halt",
                "pattern": "rm.*-rf",
                "condition": None,
            },
            {
                "id": "cli-inv-002",
                "description": "Named condition check",
                "verdict": "warn",
                "pattern": None,
                "condition": "is_destructive",
            },
        ],
    }
    return c


# -- api_permissions shapes (4 vectors) --

def _v2_api_empty() -> dict:
    c = _base()
    c["api_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "endpoints": [],
        "invariants": [],
    }
    return c


def _v2_api_min() -> dict:
    c = _base()
    c["api_permissions"] = {
        "endpoints": [
            {"id": "api-001", "url_pattern": "https://api.example.com/*", "authority": "can_execute"},
        ],
    }
    return c


def _v2_api_all_fields() -> dict:
    c = _base()
    c["api_permissions"] = {
        "mode": "permissive",
        "justification_required": False,
        "endpoints": [
            {
                "id": "api-001",
                "url_pattern": "https://api.example.com/data/*",
                "authority": "can_execute",
                "methods": ["GET", "POST"],
                "description": "Allow data API",
                "escalation_target": None,
            },
        ],
        "invariants": [],
    }
    return c


def _v2_api_with_invariants() -> dict:
    c = _base()
    c["api_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "endpoints": [],
        "invariants": [
            {
                "id": "api-inv-001",
                "description": "No PII endpoints",
                "verdict": "halt",
                "pattern": ".*/pii/.*",
            },
        ],
    }
    return c


# -- composition (2 vectors) --

def _v2_composition_default() -> dict:
    c = _base()
    c["composition"] = {"escalation_visibility": "visible"}
    return c


def _v2_composition_suppressed() -> dict:
    c = _base()
    c["composition"] = {"escalation_visibility": "suppressed"}
    return c


# -- version (1 vector) --

def _v2_version_non_default() -> dict:
    c = _base()
    c["version"] = "1.1"
    return c


# -- reasoning (2 vectors) --

def _v2_reasoning_minimal() -> dict:
    c = _base()
    c["reasoning"] = {
        "require_justification_for": ["must_escalate"],
        "on_missing_justification": "block",
        "on_check_error": "block",
        "on_api_error": "block",
        "checks": {},
        "evaluate_before_escalation": True,
        "auto_deny_on_reasoning_failure": False,
    }
    return c


def _v2_reasoning_with_judge() -> dict:
    c = _base()
    c["reasoning"] = {
        "require_justification_for": ["must_escalate", "cannot_execute"],
        "on_missing_justification": "escalate",
        "on_check_error": "block",
        "on_api_error": "block",
        "checks": {
            "glc_002_minimum_substance": {"enabled": True, "min_length": 30},
        },
        "evaluate_before_escalation": True,
        "auto_deny_on_reasoning_failure": True,
        "judge": {
            "default_provider": "anthropic",
            "default_model": None,
            "cross_provider": False,
        },
    }
    return c


# -- combined (1 vector) --

def _v2_combined_all_features() -> dict:
    c = _base_with_authority()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "decisions involving PII",
            "target": {"type": "webhook", "url": "https://audit.example.com/escalate"},
        },
    ]
    c["composition"] = {"escalation_visibility": "suppressed"}
    c["cli_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "inspect_scripts": True,
        "commands": [
            {
                "id": "cli-001",
                "binary": "git",
                "authority": "can_execute",
                "argv_pattern": "*",
                "description": "git operations",
                "escalation_target": None,
            },
        ],
        "invariants": [
            {
                "id": "cli-inv-001",
                "description": "Block dangerous rm",
                "verdict": "halt",
                "pattern": "rm.*-rf",
                "condition": None,
            },
        ],
    }
    c["api_permissions"] = {
        "mode": "strict",
        "justification_required": True,
        "endpoints": [
            {
                "id": "api-001",
                "url_pattern": "https://internal.example.com/*",
                "authority": "can_execute",
                "methods": ["GET"],
                "description": "Internal read-only API",
                "escalation_target": None,
            },
        ],
        "invariants": [],
    }
    c["version"] = "2.0"
    c["reasoning"] = {
        "require_justification_for": ["must_escalate"],
        "on_missing_justification": "block",
        "on_check_error": "block",
        "on_api_error": "block",
        "checks": {},
        "evaluate_before_escalation": True,
        "auto_deny_on_reasoning_failure": False,
    }
    return c


# -- Vector registry --

VECTORS = [
    (
        "v2_must_escalate_target_no_optionals",
        "v2 form: target has only `type`; url and handler absent in source (SAN-490 canonical case under v2)",
        _v2_target_no_optionals,
    ),
    (
        "v2_must_escalate_target_url_only",
        "v2 form: target has type + url; handler absent in source",
        _v2_target_url_only,
    ),
    (
        "v2_must_escalate_target_handler_only",
        "v2 form: target has type + handler; url absent in source",
        _v2_target_handler_only,
    ),
    (
        "v2_must_escalate_target_null",
        "v2 form: target=null (explicit null target)",
        _v2_target_null,
    ),
    (
        "v2_must_escalate_target_all_fields",
        "v2 form: target has type + url + handler (full shape)",
        _v2_target_all_fields,
    ),
    (
        "v2_cli_permissions_empty",
        "v2 form: cli_permissions present with empty commands and invariants; inspect_scripts defaults to false",
        _v2_cli_empty,
    ),
    (
        "v2_cli_permissions_one_command_minimum_fields",
        "v2 form: one command with only required fields; argv_pattern/description/escalation_target emitted at defaults",
        _v2_cli_min_fields,
    ),
    (
        "v2_cli_permissions_one_command_all_fields",
        "v2 form: one command with all fields populated; escalation_target=null emitted explicitly",
        _v2_cli_all_fields,
    ),
    (
        "v2_cli_permissions_inspect_scripts_true",
        "v2 form: inspect_scripts=true (Python-only field, formalized in schema v1.1.0)",
        _v2_cli_inspect_scripts,
    ),
    (
        "v2_cli_permissions_with_invariants",
        "v2 form: cli invariants with pattern=non-null/condition=null and pattern=null/condition=non-null",
        _v2_cli_with_invariants,
    ),
    (
        "v2_api_permissions_empty",
        "v2 form: api_permissions present with empty endpoints and invariants",
        _v2_api_empty,
    ),
    (
        "v2_api_permissions_one_endpoint_minimum",
        "v2 form: one endpoint with only required fields; methods/description/escalation_target emitted at defaults",
        _v2_api_min,
    ),
    (
        "v2_api_permissions_one_endpoint_all_fields",
        "v2 form: one endpoint with all fields; methods=[GET,POST]; escalation_target=null explicitly emitted",
        _v2_api_all_fields,
    ),
    (
        "v2_api_permissions_with_invariants",
        "v2 form: api invariant with pattern field",
        _v2_api_with_invariants,
    ),
    (
        "v2_composition_default",
        "v2 form: composition present at default (escalation_visibility=visible); emitted even at default per v2 rule",
        _v2_composition_default,
    ),
    (
        "v2_composition_suppressed",
        "v2 form: composition with escalation_visibility=suppressed",
        _v2_composition_suppressed,
    ),
    (
        "v2_version_non_default",
        "v2 form: version='1.1' (non-default); emitted in canonical bytes per v2 rule",
        _v2_version_non_default,
    ),
    (
        "v2_reasoning_minimal",
        "v2 form: minimal reasoning config (no checks, no judge); all fields emitted explicitly",
        _v2_reasoning_minimal,
    ),
    (
        "v2_reasoning_with_judge_config",
        "v2 form: reasoning with judge config and one named check (glc_002_minimum_substance)",
        _v2_reasoning_with_judge,
    ),
    (
        "v2_combined_all_features",
        "v2 form: all optional features combined (authority_boundaries, composition, cli_permissions, api_permissions, version, reasoning)",
        _v2_combined_all_features,
    ),
]


# -- Generation --

def main() -> None:
    vectors = []
    seen_ids: set = set()

    for vid, description, factory in VECTORS:
        if vid in seen_ids:
            print(f"Duplicate vector id: {vid}", file=sys.stderr)
            sys.exit(1)
        seen_ids.add(vid)

        input_dict = factory()
        const = parse_constitution(input_dict)
        policy_hash = compute_constitution_hash(const)
        input_dict["policy_hash"] = policy_hash

        signable = build_v2_signable_dict(input_dict)
        canonical_bytes = canonical_json_bytes(signable)
        canonical_str = canonical_bytes.decode("utf-8")
        sha256_hex = hashlib.sha256(canonical_bytes).hexdigest()

        vectors.append({
            "id": vid,
            "description": description,
            "input_constitution": input_dict,
            "expected_signable_canonical_json": canonical_str,
            "expected_signable_sha256": sha256_hex,
        })

    output = {
        "spec_version": "1.5",
        "san_ticket": "SAN-492",
        "signing_version": 2,
        "description": (
            "Cross-SDK byte-equal contract for the v2 unified canonical signable "
            "form. A conformant SDK MUST, for every vector, parse "
            "input_constitution, compute v2 canonical bytes via its "
            "canonicalization pipeline (signing_version=2), and produce "
            "expected_signable_canonical_json byte-for-byte. "
            "expected_signable_sha256 cross-checks. See spec Section 5.3 "
            "for the v2 form definition; Section 13.6 for the conformance "
            "requirement."
        ),
        "vectors": vectors,
        "test_protocol": {
            "python_sdk": (
                "from sanna.constitution import parse_constitution, constitution_to_signable_dict_v2; "
                "from sanna.hashing import canonical_json_bytes; "
                "const = parse_constitution(v['input_constitution']); "
                "canonical = canonical_json_bytes(constitution_to_signable_dict_v2(const)).decode('utf-8'); "
                "assert canonical == v['expected_signable_canonical_json']"
            ),
            "ts_sdk": (
                "import { parseConstitution, computeCanonicalSignableJsonV2 } from '@sanna-ai/core'; "
                "const c = parseConstitution(v.input_constitution); "
                "const canonical = computeCanonicalSignableJsonV2(c); "
                "expect(canonical).toBe(v.expected_signable_canonical_json);"
            ),
        },
    }

    VECTORS_PATH.write_text(
        json.dumps(output, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    print(f"Wrote {VECTORS_PATH} with {len(vectors)} vectors")


if __name__ == "__main__":
    main()
