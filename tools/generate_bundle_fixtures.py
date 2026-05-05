#!/usr/bin/env python3
"""
Generate cross-SDK bundle forge fixture for SAN-403.

Creates:
  fixtures/bundles/genuine.bundle.zip
  fixtures/bundles/forged.bundle.zip
  fixtures/keypairs/test-attacker.{key,pub,meta.json}
  fixtures/bundle-trust-vectors.json
  (updates fixtures/golden-hashes.json to add test_attacker_key_id)

The vectors file is byte-stable across runs (idempotent on keypair + key_ids).
The ZIP files may regenerate across runs (zip timestamps, signed_at differ).

Usage:
    python3 tools/generate_bundle_fixtures.py
"""

import copy
import json
import os
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    root = repo_root()
    fixtures = root / "fixtures"

    # ---------------------------------------------------------------------------
    # Step 1: Load genuine author keypair
    # ---------------------------------------------------------------------------
    from sanna.crypto import (
        compute_key_id,
        canonical_json_bytes,
        sanitize_for_signing,
        sign_bytes,
        load_private_key,
        load_public_key,
        _sign_receipt_with_key,
    )

    author_key_path = fixtures / "keypairs" / "test-author.key"
    author_pub_path = fixtures / "keypairs" / "test-author.pub"

    author_private_key = load_private_key(author_key_path)
    author_public_key = load_public_key(author_pub_path)
    genuine_key_id = compute_key_id(author_public_key)

    # ---------------------------------------------------------------------------
    # Step 2: Idempotent attacker keypair
    # ---------------------------------------------------------------------------
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    attacker_key_path = fixtures / "keypairs" / "test-attacker.key"
    attacker_pub_path = fixtures / "keypairs" / "test-attacker.pub"
    attacker_meta_path = fixtures / "keypairs" / "test-attacker.meta.json"

    if attacker_key_path.exists():
        attacker_private_key = load_private_key(attacker_key_path)
        attacker_public_key = load_public_key(attacker_pub_path)
        attacker_key_id = compute_key_id(attacker_public_key)
    else:
        attacker_private_key = Ed25519PrivateKey.generate()
        attacker_public_key = attacker_private_key.public_key()
        attacker_key_id = compute_key_id(attacker_public_key)

        priv_pem = attacker_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        pub_pem = attacker_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        attacker_key_path.write_bytes(priv_pem)
        os.chmod(attacker_key_path, 0o600)
        attacker_pub_path.write_bytes(pub_pem)

        meta = {
            "key_id": attacker_key_id,
            "created_at": now_iso(),
            "algorithm": "Ed25519",
            "label": "test-attacker",
            "signed_by": "test-attacker@sanna.dev",
        }
        attacker_meta_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )

    # ---------------------------------------------------------------------------
    # Step 3: Load genuine constitution; build fresh bundle receipt
    #
    # The existing pass-single-check.json lacks constitution_ref, which the
    # SDK 1.5 provenance-chain check requires. We generate a bundle-specific
    # receipt using generate_receipt() with ConstitutionProvenance pointing at
    # minimal.yaml. The resulting constitution_ref contains policy_hash but no
    # signature field; _verify_provenance_chain skips the signature sub-check
    # when the field is absent, so the forged bundle (which only rotates
    # receipt_signature and constitution.provenance.signature) passes the
    # provenance chain check unchanged.
    # ---------------------------------------------------------------------------
    from sanna.constitution import (
        ConstitutionSignature,
        constitution_to_dict,
        constitution_to_signable_dict,
        load_constitution,
    )
    from sanna.receipt import ConstitutionProvenance
    from sanna import generate_receipt, receipt_to_dict
    import yaml

    constitution_path = fixtures / "constitutions" / "minimal.yaml"
    genuine_constitution = load_constitution(constitution_path)
    genuine_constitution_bytes = constitution_path.read_bytes()
    author_pub_bytes = author_pub_path.read_bytes()

    prov = ConstitutionProvenance(
        document_id="test-minimal-agent/1.0.0",
        policy_hash=genuine_constitution.policy_hash,
        version="1.0.0",
        source="fixtures/constitutions/minimal.yaml",
    )
    trace_data = {
        "correlation_id": "sanna-bundle-fixture-san-403",
        "observations": [],
        "final_answer": "fixture answer",
        "context": "fixture context",
        "output": "fixture output",
    }
    receipt_obj = generate_receipt(
        trace_data,
        constitution=prov,
        enforcement_surface="middleware",
        invariants_scope="full",
        agent_model="fixture-model",
        agent_model_provider="fixture-provider",
        agent_model_version="0.0.0",
        agent_identity={"agent_session_id": "sanna-bundle-fixture-san-403-session"},
    )
    genuine_receipt_dict = receipt_to_dict(receipt_obj)
    _sign_receipt_with_key(genuine_receipt_dict, author_private_key, signed_by="test-author@sanna.dev")
    genuine_receipt_bytes = (
        json.dumps(genuine_receipt_dict, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")

    # ---------------------------------------------------------------------------
    # Step 4: Build the GENUINE bundle
    # ---------------------------------------------------------------------------
    import sanna
    tool_version = sanna.__version__

    bundles_dir = fixtures / "bundles"
    bundles_dir.mkdir(exist_ok=True)

    genuine_metadata = {
        "bundle_format_version": "1.0.0",
        "created_at": now_iso(),
        "tool_version": tool_version,
        "description": "Genuine bundle for SAN-403 cross-SDK trust anchor vectors",
    }

    genuine_zip_path = bundles_dir / "genuine.bundle.zip"
    with zipfile.ZipFile(genuine_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("receipt.json", genuine_receipt_bytes)
        zf.writestr("constitution.yaml", genuine_constitution_bytes)
        zf.writestr(
            f"public_keys/{genuine_key_id}.pub",
            author_pub_bytes,
        )
        zf.writestr(
            "metadata.json",
            json.dumps(genuine_metadata, indent=2, ensure_ascii=True) + "\n",
        )

    # ---------------------------------------------------------------------------
    # Step 5: Build the FORGED bundle
    #
    # CRITICAL: The receipt fingerprint and constitution policy_hash are
    # content-derived (signature-excluded). Body content stays unchanged; only
    # signature blocks rotate. DO NOT recompute the fingerprint or policy_hash.
    #
    # constitution_ref in the receipt has no "signature" field, so
    # _verify_provenance_chain skips the signature sub-check. The forged receipt
    # keeps constitution_ref unchanged; fingerprint stays valid.
    # ---------------------------------------------------------------------------

    # 5a. Forged receipt: swap receipt_signature, sign with attacker key
    forged_receipt = copy.deepcopy(genuine_receipt_dict)
    forged_receipt["receipt_signature"] = {
        "signature": "",
        "key_id": attacker_key_id,
        "signed_by": "test-attacker@sanna.dev",
        "signed_at": now_iso(),
        "scheme": "receipt_sig_v1",
    }
    signable_receipt_data = canonical_json_bytes(sanitize_for_signing(forged_receipt))
    forged_receipt_sig = sign_bytes(signable_receipt_data, attacker_private_key)
    forged_receipt["receipt_signature"]["signature"] = forged_receipt_sig

    forged_receipt_bytes = (
        json.dumps(forged_receipt, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")

    # 5b. Forged constitution: swap provenance.signature, sign with attacker key
    forged_constitution = copy.deepcopy(genuine_constitution)
    forged_constitution.provenance.signature = ConstitutionSignature(
        value="",
        key_id=attacker_key_id,
        signed_by="test-attacker@sanna.dev",
        signed_at=now_iso(),
        scheme="constitution_sig_v1",
    )

    signable_const_dict = constitution_to_signable_dict(forged_constitution)
    signable_const_data = canonical_json_bytes(sanitize_for_signing(signable_const_dict))
    forged_const_sig = sign_bytes(signable_const_data, attacker_private_key)
    forged_constitution.provenance.signature.value = forged_const_sig

    forged_const_dict = constitution_to_dict(forged_constitution)
    forged_constitution_yaml = yaml.dump(
        forged_const_dict, default_flow_style=False, sort_keys=False, allow_unicode=False
    )
    forged_constitution_bytes = forged_constitution_yaml.encode("ascii")

    attacker_pub_bytes = attacker_pub_path.read_bytes()

    # 5c. Forged metadata
    forged_metadata = {
        "bundle_format_version": "1.0.0",
        "created_at": now_iso(),
        "tool_version": tool_version,
        "description": (
            "Forged bundle (re-signed by test-attacker) for SAN-403 cross-SDK "
            "trust anchor vectors -- DO NOT TRUST IN PRODUCTION"
        ),
    }

    # 5d. Write forged bundle ZIP
    forged_zip_path = bundles_dir / "forged.bundle.zip"
    with zipfile.ZipFile(forged_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("receipt.json", forged_receipt_bytes)
        zf.writestr("constitution.yaml", forged_constitution_bytes)
        zf.writestr(
            f"public_keys/{attacker_key_id}.pub",
            attacker_pub_bytes,
        )
        zf.writestr(
            "metadata.json",
            json.dumps(forged_metadata, indent=2, ensure_ascii=True) + "\n",
        )

    # ---------------------------------------------------------------------------
    # Step 6: Write fixtures/bundle-trust-vectors.json
    # ---------------------------------------------------------------------------
    vectors = {
        "spec_version": "1.5",
        "san_ticket": "SAN-403",
        "description": (
            "Cross-SDK assertions for the bundle verifier trust anchor (SAN-403). "
            "A conformant verifier MUST produce, for every vector, a "
            "BundleVerificationResult whose valid and trust_anchored fields match the "
            "expect block. See spec Section 10.1 and Section 13.4."
        ),
        "genuine_key_id": genuine_key_id,
        "attacker_key_id": attacker_key_id,
        "bundles": {
            "genuine": "fixtures/bundles/genuine.bundle.zip",
            "forged": "fixtures/bundles/forged.bundle.zip",
        },
        "vectors": [
            {
                "id": "genuine_no_anchor",
                "bundle": "genuine",
                "trusted_key_ids": None,
                "expect": {"valid": True, "trust_anchored": False},
            },
            {
                "id": "genuine_anchor_match",
                "bundle": "genuine",
                "trusted_key_ids": [genuine_key_id],
                "expect": {"valid": True, "trust_anchored": True},
            },
            {
                "id": "genuine_anchor_excluding",
                "bundle": "genuine",
                "trusted_key_ids": [
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ],
                "expect": {"valid": False, "trust_anchored": True},
            },
            {
                "id": "genuine_empty_anchor_fails_closed",
                "bundle": "genuine",
                "trusted_key_ids": [],
                "expect": {"valid": False, "trust_anchored": True},
                "rationale": (
                    "Empty Set is the explicit 'trust nothing' signal. Verifiers "
                    "MUST NOT special-case empty as equivalent to null."
                ),
            },
            {
                "id": "forged_no_anchor_self_consistent",
                "bundle": "forged",
                "trusted_key_ids": None,
                "expect": {"valid": True, "trust_anchored": False},
                "rationale": (
                    "The bug SAN-403 closes: a forged bundle is internally "
                    "self-consistent and passes without an anchor. Operators see a "
                    "stderr warning banner; the JSON result has trust_anchored: false."
                ),
            },
            {
                "id": "forged_anchored_genuine_only_caught",
                "bundle": "forged",
                "trusted_key_ids": [genuine_key_id],
                "expect": {"valid": False, "trust_anchored": True},
                "rationale": "The fix: an anchor listing only the genuine key catches the forge.",
            },
            {
                "id": "forged_anchored_attacker_passes_sanity",
                "bundle": "forged",
                "trusted_key_ids": [attacker_key_id],
                "expect": {"valid": True, "trust_anchored": True},
                "rationale": (
                    "Sanity check: a misconfigured anchor that lists the attacker key "
                    "still passes. Trust anchor is necessary but not sufficient -- "
                    "operators MUST curate the anchor; merely supplying one does not "
                    "provide assurance."
                ),
            },
        ],
        "test_protocol": {
            "python_sdk": (
                "from sanna.bundle import verify_bundle; "
                "tk = set(v['trusted_key_ids']) if v['trusted_key_ids'] is not None else None; "
                "r = verify_bundle(<bundle_path>, trusted_key_ids=tk); "
                "assert r.valid == v['expect']['valid'] and r.trust_anchored == v['expect']['trust_anchored']"
            ),
            "ts_sdk": (
                "import { verifyBundle } from '@sanna-ai/core'; "
                "const tk = v.trusted_key_ids === null ? null : new Set(v.trusted_key_ids); "
                "const r = verifyBundle(<bundlePath>, true, tk); "
                "expect(r.valid).toBe(v.expect.valid); "
                "expect(r.trust_anchored).toBe(v.expect.trust_anchored)"
            ),
        },
    }

    vectors_path = fixtures / "bundle-trust-vectors.json"
    vectors_path.write_text(
        json.dumps(vectors, indent=2, sort_keys=False, ensure_ascii=True) + "\n",
        encoding="ascii",
    )

    # ---------------------------------------------------------------------------
    # Step 7: Update golden-hashes.json -- add test_attacker_key_id
    # ---------------------------------------------------------------------------
    golden_path = fixtures / "golden-hashes.json"
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    if "test_attacker_key_id" not in golden:
        updated: dict = {}
        for k, v in golden.items():
            updated[k] = v
            if k == "test_key_id":
                updated["test_attacker_key_id"] = attacker_key_id
        golden = updated
    else:
        golden["test_attacker_key_id"] = attacker_key_id

    golden_path.write_text(
        json.dumps(golden, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )

    print("Done.")
    print(f"  genuine_key_id  : {genuine_key_id}")
    print(f"  attacker_key_id : {attacker_key_id}")
    print(f"  genuine.bundle.zip : {genuine_zip_path}")
    print(f"  forged.bundle.zip  : {forged_zip_path}")
    print(f"  bundle-trust-vectors.json : {vectors_path}")


if __name__ == "__main__":
    main()
