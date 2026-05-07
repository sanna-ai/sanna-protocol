#!/usr/bin/env python3
"""Generate fixtures/constitution-signable-vectors.json and fill policy_hash on with-authority-target.yaml.

SAN-490: cross-SDK byte-equal contract for constitution_to_signable_dict's output,
focused on must_escalate.target null-handling. Both Python and TypeScript SDKs MUST
produce byte-identical canonical signable JSON for each vector input.

Usage:
    python3 tools/generate_signable_vectors.py
"""

import dataclasses
import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import yaml

from sanna.constitution import (
    Constitution,
    compute_constitution_hash,
    constitution_to_signable_dict,
    parse_constitution,
)
from sanna.hashing import canonical_json_bytes

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
VECTORS_PATH = FIXTURES / "constitution-signable-vectors.json"
SUPPORT_YAML = FIXTURES / "constitutions" / "with-authority-target.yaml"

# Fixed date for deterministic output
FIXED_APPROVAL_DATE = "2026-05-06"


# -- Vector input factories --------------------------------------------------

def _base() -> dict:
    """Minimal valid Constitution dict; each vector adds its must_escalate variant."""
    return {
        "sanna_constitution": "1.0.1",
        "identity": {
            "agent_name": "san-490-vector-agent",
            "domain": "testing",
            "description": "Cross-SDK signable parity vector",
        },
        "provenance": {
            "authored_by": "test-author@sanna.dev",
            "approved_by": ["test-author@sanna.dev"],
            "approval_date": FIXED_APPROVAL_DATE,
            "approval_method": "vector-generation",
            "change_history": [],
        },
        "boundaries": [
            {
                "id": "B001",
                "description": "Vector test boundary",
                "category": "scope",
                "severity": "medium",
            },
        ],
        "trust_tiers": {
            "autonomous": [],
            "requires_approval": [],
            "prohibited": [],
        },
        "halt_conditions": [],
        "invariants": [],
        "authority_boundaries": {
            "cannot_execute": [],
            "must_escalate": [],
            "can_execute": [],
        },
    }


def _must_escalate_target_no_optionals() -> dict:
    c = _base()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target with no optional fields",
            "target": {"type": "log"},
        },
    ]
    return c


def _must_escalate_target_url_only() -> dict:
    c = _base()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target with url only",
            "target": {"type": "webhook", "url": "https://example.com/escalations"},
        },
    ]
    return c


def _must_escalate_target_handler_only() -> dict:
    c = _base()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target with handler only",
            "target": {"type": "callback", "handler": "review_handler"},
        },
    ]
    return c


def _must_escalate_target_null() -> dict:
    c = _base()
    c["authority_boundaries"]["must_escalate"] = [
        {
            "condition": "target=null",
            "target": None,
        },
    ]
    return c


def _must_escalate_target_all_fields() -> dict:
    c = _base()
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


VECTORS_SPEC = [
    (
        "must_escalate_target_no_optionals",
        "target has only `type`; url and handler absent in source dict (SAN-490 canonical bug case)",
        _must_escalate_target_no_optionals,
    ),
    (
        "must_escalate_target_url_only",
        "target has type + url; handler absent in source",
        _must_escalate_target_url_only,
    ),
    (
        "must_escalate_target_handler_only",
        "target has type + handler; url absent in source",
        _must_escalate_target_handler_only,
    ),
    (
        "must_escalate_target_null",
        "target=null (explicit null target; regression guard for both SDKs)",
        _must_escalate_target_null,
    ),
    (
        "must_escalate_target_all_fields",
        "target has type + url + handler (full-shape regression guard)",
        _must_escalate_target_all_fields,
    ),
]


# -- Generation --------------------------------------------------------------

def _generate_vector(vid: str, description: str, factory) -> dict:
    input_dict = factory()

    const = parse_constitution(input_dict)
    policy_hash = compute_constitution_hash(const)
    const_with_hash = dataclasses.replace(const, policy_hash=policy_hash)

    signable = constitution_to_signable_dict(const_with_hash)
    canonical_bytes = canonical_json_bytes(signable)
    canonical_str = canonical_bytes.decode("ascii")
    sha256_hex = hashlib.sha256(canonical_bytes).hexdigest()

    input_dict_with_hash = deepcopy(input_dict)
    input_dict_with_hash["policy_hash"] = policy_hash

    return {
        "id": vid,
        "description": description,
        "input_constitution": input_dict_with_hash,
        "expected_signable_canonical_json": canonical_str,
        "expected_signable_sha256": sha256_hex,
    }


def main() -> None:
    vectors = [_generate_vector(vid, desc, factory) for vid, desc, factory in VECTORS_SPEC]

    output = {
        "spec_version": "1.5",
        "san_ticket": "SAN-490",
        "description": (
            "Cross-SDK byte-equal contract for constitution_to_signable_dict output. "
            "A conformant SDK MUST, for every vector, parse the input_constitution dict, "
            "run its constitution_to_signable_dict equivalent, canonicalize via its "
            "RFC 8785-style canonical_json, and produce expected_signable_canonical_json "
            "byte-for-byte. expected_signable_sha256 is a fast cross-check. "
            "See spec Section 6.9 for the canonical form definition."
        ),
        "vectors": vectors,
        "test_protocol": {
            "python_sdk": (
                "from sanna.constitution import parse_constitution, compute_constitution_hash, "
                "constitution_to_signable_dict; "
                "import dataclasses; "
                "from sanna.hashing import canonical_json_bytes; "
                "const = parse_constitution(v['input_constitution']); "
                "const = dataclasses.replace(const, policy_hash=v['input_constitution']['policy_hash']); "
                "signable = constitution_to_signable_dict(const); "
                "canonical = canonical_json_bytes(signable).decode('ascii'); "
                "assert canonical == v['expected_signable_canonical_json']"
            ),
            "ts_sdk": (
                "import { parseConstitutionDict, constitutionToSignableDict, canonicalJsonBytes } "
                "from '@sanna-ai/core'; "
                "const c = parseConstitutionDict(v.input_constitution); "
                "const signable = constitutionToSignableDict(c); "
                "const canonical = canonicalJsonBytes(signable).toString('utf-8'); "
                "expect(canonical).toBe(v.expected_signable_canonical_json);"
            ),
        },
    }

    VECTORS_PATH.write_text(
        json.dumps(output, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    print(f"Wrote {VECTORS_PATH}")

    # Fill policy_hash on the supporting YAML
    yaml_text = SUPPORT_YAML.read_text(encoding="ascii")
    placeholder = "policy_hash: <will be computed by tools/generate_signable_vectors.py and substituted>"
    if placeholder in yaml_text:
        yaml_doc = yaml.safe_load(yaml_text)
        # Remove placeholder so parse_constitution can handle missing policy_hash
        yaml_doc.pop("policy_hash", None)
        yaml_const = parse_constitution(yaml_doc)
        yaml_policy_hash = compute_constitution_hash(yaml_const)
        new_text = yaml_text.replace(
            placeholder,
            f"policy_hash: {yaml_policy_hash}",
        )
        SUPPORT_YAML.write_text(new_text, encoding="ascii")
        print(f"Filled policy_hash on {SUPPORT_YAML}: {yaml_policy_hash}")
    else:
        # Already has a real hash; verify it is still correct
        yaml_doc = yaml.safe_load(yaml_text)
        yaml_doc.pop("policy_hash", None)
        yaml_const = parse_constitution(yaml_doc)
        expected_hash = compute_constitution_hash(yaml_const)
        stored_hash = yaml.safe_load(yaml_text).get("policy_hash", "")
        if expected_hash != stored_hash:
            print(
                f"WARNING: {SUPPORT_YAML} policy_hash mismatch "
                f"(stored={stored_hash[:8]}..., expected={expected_hash[:8]}...)",
                file=sys.stderr,
            )
        else:
            print(f"policy_hash on {SUPPORT_YAML} verified: {expected_hash[:16]}...")


if __name__ == "__main__":
    main()
