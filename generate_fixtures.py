#!/usr/bin/env python3
"""Generate golden test fixtures for the Sanna Protocol spec repo.

This script generates:
  - fixtures/keypairs/test-author.key and test-author.pub
  - fixtures/constitutions/minimal.yaml (signed) + minimal.yaml.sig
  - fixtures/constitutions/full-featured.yaml
  - fixtures/receipts/pass-single-check.json
  - fixtures/receipts/fail-halted.json
  - fixtures/receipts/escalated.json
  - fixtures/receipts/full-featured.json
  - fixtures/golden-hashes.json

Run from the repo root:
    python generate_fixtures.py
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────
REPO = Path(__file__).parent
FIXTURES = REPO / "fixtures"
KEYPAIRS = FIXTURES / "keypairs"
CONSTITUTIONS = FIXTURES / "constitutions"
RECEIPTS = FIXTURES / "receipts"

# ── Ensure sanna is importable ───────────────────────────────────────
try:
    from sanna.crypto import (
        load_private_key,
        load_public_key,
        compute_key_id,
        sign_receipt,
        sanitize_for_signing,
        canonical_json_bytes,
    )
    from sanna.hashing import (
        EMPTY_HASH,
        hash_text,
        hash_obj,
    )
    from sanna.receipt import (
        generate_receipt,
        SannaReceipt,
        SPEC_VERSION,
        CHECKS_VERSION,
        TOOL_VERSION,
    )
except ImportError:
    print("ERROR: sanna package not installed. Run: pip install sanna")
    sys.exit(1)


def ensure_dirs():
    for d in [KEYPAIRS, CONSTITUTIONS, RECEIPTS]:
        d.mkdir(parents=True, exist_ok=True)


# ── Step 1: Generate dedicated test keypair ──────────────────────────

def generate_test_keypair():
    """Generate an Ed25519 keypair and write PEM files to fixtures/keypairs/."""
    print("[1/6] Generating test keypair...")

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(
            ["sanna", "keygen", "--output-dir", tmpdir, "--label", "test-author",
             "--signed-by", "test-author@sanna.dev"],
            check=True, capture_output=True, text=True,
        )
        key_files = list(Path(tmpdir).glob("*.key"))
        if not key_files:
            print("ERROR: No key file generated")
            sys.exit(1)

        key_id = key_files[0].stem
        src_key = Path(tmpdir) / f"{key_id}.key"
        src_pub = Path(tmpdir) / f"{key_id}.pub"

        shutil.copy2(src_key, KEYPAIRS / "test-author.key")
        shutil.copy2(src_pub, KEYPAIRS / "test-author.pub")

        meta = Path(tmpdir) / f"{key_id}.meta.json"
        if meta.exists():
            shutil.copy2(meta, KEYPAIRS / "test-author.meta.json")

    pub = load_public_key(str(KEYPAIRS / "test-author.pub"))
    kid = compute_key_id(pub)
    priv_path = str(KEYPAIRS / "test-author.key")
    pub_path = str(KEYPAIRS / "test-author.pub")
    print(f"  Key ID: {kid}")
    return priv_path, pub_path, kid


# ── Step 2: Create constitutions ─────────────────────────────────────

MINIMAL_CONSTITUTION = """\
sanna_constitution: "1.0.0"

identity:
  agent_name: test-minimal-agent
  domain: testing
  description: Minimal valid constitution for cross-language fixture testing

provenance:
  authored_by: test-author@sanna.dev
  approved_by: test-author@sanna.dev
  approval_date: "2026-02-22"
  approval_method: fixture-generation

boundaries:
  - id: B001
    description: Agent operates within testing scope only
    category: scope
    severity: high

invariants:
  - id: INV_NO_FABRICATION
    rule: Agent must not fabricate information absent from provided context
    enforcement: halt
    check: sanna.context_contradiction
"""

FULL_CONSTITUTION = """\
sanna_constitution: "1.0.0"

identity:
  agent_name: test-full-agent
  domain: testing
  description: Full-featured constitution exercising all schema sections

provenance:
  authored_by: test-author@sanna.dev
  approved_by:
    - test-author@sanna.dev
    - test-reviewer@sanna.dev
  approval_date: "2026-02-22"
  approval_method: dual-review

boundaries:
  - id: B001
    description: Agent operates within testing scope only
    category: scope
    severity: high
  - id: B002
    description: Agent must not access credentials
    category: confidentiality
    severity: critical
  - id: B003
    description: Agent must follow safety constraints
    category: safety
    severity: critical

authority_boundaries:
  can_execute:
    - "*_read"
    - "*_search"
    - "*_list"
  must_escalate:
    - condition: "Any write or create operation"
    - condition: "Any delete operation"
      target:
        type: webhook
        url: "https://example.com/escalations"
  cannot_execute:
    - "*_credential*"
    - "shell_*"

halt_conditions:
  - id: H001
    trigger: Critical check failure in context contradiction detection
    escalate_to: test-author@sanna.dev
    severity: critical
    enforcement: halt
  - id: H002
    trigger: Unauthorized access to prohibited resource
    escalate_to: test-author@sanna.dev
    severity: high
    enforcement: halt

trust_tiers:
  autonomous:
    - "*_read"
    - "*_search"
  requires_approval:
    - "*_write"
    - "*_delete"
  prohibited:
    - "*_credential*"

invariants:
  - id: INV_NO_FABRICATION
    rule: Agent must not fabricate information absent from provided context
    enforcement: halt
    check: sanna.context_contradiction
  - id: INV_MARK_INFERENCE
    rule: Agent must clearly mark inferences that go beyond source material
    enforcement: warn
    check: sanna.unmarked_inference
  - id: INV_NO_FALSE_CERTAINTY
    rule: Agent must not express certainty beyond what evidence supports
    enforcement: warn
    check: sanna.false_certainty
  - id: INV_PRESERVE_TENSION
    rule: Agent must preserve conflicting evidence without collapsing to a single narrative
    enforcement: warn
    check: sanna.conflict_collapse
  - id: INV_NO_PREMATURE_COMPRESSION
    rule: Agent must not reduce nuanced situations to simple summaries prematurely
    enforcement: log
    check: sanna.premature_compression

trusted_sources:
  tier_1:
    - internal-database
    - verified-api
  tier_2:
    - partner-api
  tier_3:
    - public-web
  untrusted:
    - user-input

escalation_targets:
  default: log
"""


def create_constitutions(priv_key_path):
    """Write and sign constitution fixtures."""
    print("[2/6] Creating constitutions...")

    minimal_path = CONSTITUTIONS / "minimal.yaml"
    minimal_path.write_text(MINIMAL_CONSTITUTION)

    full_path = CONSTITUTIONS / "full-featured.yaml"
    full_path.write_text(FULL_CONSTITUTION)

    # Sign minimal using sanna CLI
    print("  Signing minimal.yaml...")
    result = subprocess.run(
        ["sanna", "sign", str(minimal_path),
         "--private-key", priv_key_path,
         "--signed-by", "test-author@sanna.dev"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  Warning: sanna sign returned {result.returncode}")
        if result.stderr:
            print(f"  stderr: {result.stderr.strip()}")

    sig_path = CONSTITUTIONS / "minimal.yaml.sig"
    if not sig_path.exists():
        print("  Note: Signature embedded in YAML (no separate .sig file)")

    print(f"  Wrote: {minimal_path}")
    print(f"  Wrote: {full_path}")


# ── Trace data helpers ───────────────────────────────────────────────

def make_trace(correlation_id, query, context, response):
    """Build a trace_data dict for generate_receipt().

    The sanna generate_receipt() expects:
      - correlation_id: string
      - output: dict with 'response' or 'final_answer'
      - observations: list of dicts (optional)
    """
    return {
        "correlation_id": correlation_id,
        "output": {"response": response},
        "observations": [
            {
                "name": "retrieval",
                "input": {"query": query},
                "output": {"context": context},
            }
        ],
    }


def receipt_to_dict(r: SannaReceipt) -> dict:
    """Convert SannaReceipt dataclass to a JSON-serializable dict."""
    from dataclasses import asdict
    d = asdict(r)
    return {k: v for k, v in d.items() if v is not None}


# ── Fingerprint recomputation ────────────────────────────────────────

def recompute_fingerprint(receipt_dict):
    """Recompute fingerprint fields after modifying a receipt."""
    correlation_id = receipt_dict["correlation_id"]
    context_hash = receipt_dict["context_hash"]
    output_hash = receipt_dict["output_hash"]
    checks_version = receipt_dict["checks_version"]

    # checks_hash — detect format from actual check data, not from constitution_ref
    checks = receipt_dict.get("checks", [])
    has_enforcement_fields = any(c.get("triggered_by") is not None for c in checks)
    checks_data = []
    for c in checks:
        if has_enforcement_fields:
            check_entry = {
                "check_id": c.get("check_id", ""),
                "passed": c.get("passed"),
                "severity": c.get("severity", ""),
                "evidence": c.get("evidence"),
                "triggered_by": c.get("triggered_by"),
                "enforcement_level": c.get("enforcement_level"),
                "check_impl": c.get("check_impl"),
                "replayable": c.get("replayable"),
            }
        else:
            check_entry = {
                "check_id": c.get("check_id", ""),
                "passed": c.get("passed"),
                "severity": c.get("severity", ""),
                "evidence": c.get("evidence"),
            }
        checks_data.append(check_entry)
    checks_hash = hash_obj(checks_data) if checks_data else EMPTY_HASH

    # constitution_hash
    const_ref = receipt_dict.get("constitution_ref")
    if const_ref:
        stripped = {k: v for k, v in const_ref.items() if k != "constitution_approval"}
        constitution_hash = hash_obj(stripped)
    else:
        constitution_hash = EMPTY_HASH

    # Other component hashes
    enforcement = receipt_dict.get("enforcement")
    enforcement_hash = hash_obj(enforcement) if enforcement else EMPTY_HASH

    coverage = receipt_dict.get("evaluation_coverage")
    coverage_hash = hash_obj(coverage) if coverage else EMPTY_HASH

    authority = receipt_dict.get("authority_decisions")
    authority_hash = hash_obj(authority) if authority else EMPTY_HASH

    escalation = receipt_dict.get("escalation_events")
    escalation_hash = hash_obj(escalation) if escalation else EMPTY_HASH

    trust = receipt_dict.get("source_trust_evaluations")
    trust_hash = hash_obj(trust) if trust else EMPTY_HASH

    extensions = receipt_dict.get("extensions")
    extensions_hash = hash_obj(extensions) if extensions else EMPTY_HASH

    fingerprint_input = "|".join([
        correlation_id,
        context_hash,
        output_hash,
        checks_version,
        checks_hash,
        constitution_hash,
        enforcement_hash,
        coverage_hash,
        authority_hash,
        escalation_hash,
        trust_hash,
        extensions_hash,
    ])

    receipt_dict["full_fingerprint"] = hash_text(fingerprint_input, truncate=64)
    receipt_dict["receipt_fingerprint"] = hash_text(fingerprint_input, truncate=16)

    return receipt_dict


# ── Step 3: Generate receipt fixtures ────────────────────────────────

def generate_receipts(priv_key_path, pub_key_path, key_id):
    """Generate 4 receipt variants and sign them."""
    print("[3/6] Generating receipts...")

    # ── 1. pass-single-check: one passing check, status PASS ──
    trace_pass = make_trace(
        correlation_id="sanna-fixture-pass-001",
        query="What is the capital of France?",
        context="France is a country in Western Europe. Its capital is Paris.",
        response="The capital of France is Paris.",
    )
    receipt_pass = generate_receipt(trace_pass)
    receipt_pass_dict = receipt_to_dict(receipt_pass)
    receipt_pass_signed = sign_receipt(receipt_pass_dict, priv_key_path, "test-author@sanna.dev")

    pass_path = RECEIPTS / "pass-single-check.json"
    pass_path.write_text(json.dumps(receipt_pass_signed, indent=2, ensure_ascii=False) + "\n")
    print(f"  Wrote: {pass_path}")

    # ── 2. fail-halted: enforcement halt ──
    trace_fail = make_trace(
        correlation_id="sanna-fixture-fail-001",
        query="What happened in the meeting yesterday?",
        context="No meeting notes are available for yesterday.",
        response="In yesterday's meeting, the team decided to launch the product next week and approved the Q3 budget of $2.5 million.",
    )
    receipt_fail = generate_receipt(trace_fail)
    receipt_fail_dict = receipt_to_dict(receipt_fail)

    # Ensure at least one critical failure for the halt scenario
    if receipt_fail_dict.get("status") != "FAIL":
        # Force C1 to fail if it didn't naturally
        for c in receipt_fail_dict.get("checks", []):
            if c["check_id"] in ("C1", "sanna.context_contradiction"):
                c["passed"] = False
                c["severity"] = "critical"
                c["evidence"] = "Agent fabricated meeting details not present in context"
                if c.get("status") == "NOT_CHECKED":
                    c["status"] = "FAILED"
                break
        # Recount
        evaluated = [c for c in receipt_fail_dict["checks"]
                     if c.get("status") not in ("NOT_CHECKED", "ERRORED")]
        receipt_fail_dict["checks_passed"] = sum(1 for c in evaluated if c["passed"])
        receipt_fail_dict["checks_failed"] = sum(1 for c in evaluated if not c["passed"])
        receipt_fail_dict["status"] = "FAIL"

    # Add enforcement block
    failed_ids = [c["check_id"] for c in receipt_fail_dict["checks"]
                  if not c["passed"] and c.get("status") != "NOT_CHECKED"]
    receipt_fail_dict["enforcement"] = {
        "action": "halted",
        "reason": "Critical check failure: context contradiction detected",
        "failed_checks": failed_ids if failed_ids else ["C1"],
        "enforcement_mode": "halt",
        "timestamp": receipt_fail_dict["timestamp"],
    }

    receipt_fail_dict = recompute_fingerprint(receipt_fail_dict)
    receipt_fail_signed = sign_receipt(receipt_fail_dict, priv_key_path, "test-author@sanna.dev")

    fail_path = RECEIPTS / "fail-halted.json"
    fail_path.write_text(json.dumps(receipt_fail_signed, indent=2, ensure_ascii=False) + "\n")
    print(f"  Wrote: {fail_path}")

    # ── 3. escalated: must_escalate action ──
    trace_esc = make_trace(
        correlation_id="sanna-fixture-escalated-001",
        query="Delete the customer record for user 12345.",
        context="User 12345: John Doe, account active since 2023-01-15.",
        response="This action requires approval. The delete operation has been escalated.",
    )
    receipt_esc = generate_receipt(trace_esc)
    receipt_esc_dict = receipt_to_dict(receipt_esc)

    receipt_esc_dict["enforcement"] = {
        "action": "escalated",
        "reason": "Delete operation requires human approval per must_escalate policy",
        "failed_checks": [],
        "enforcement_mode": "halt",
        "timestamp": receipt_esc_dict["timestamp"],
    }

    receipt_esc_dict = recompute_fingerprint(receipt_esc_dict)
    receipt_esc_signed = sign_receipt(receipt_esc_dict, priv_key_path, "test-author@sanna.dev")

    esc_path = RECEIPTS / "escalated.json"
    esc_path.write_text(json.dumps(receipt_esc_signed, indent=2, ensure_ascii=False) + "\n")
    print(f"  Wrote: {esc_path}")

    # ── 4. full-featured: all fields populated ──
    trace_full = make_trace(
        correlation_id="sanna-fixture-full-001",
        query="Summarize the Q3 financial report and recommend next steps.",
        context="Q3 revenue: $4.2M (up 15% YoY). Operating expenses: $3.1M. Net income: $1.1M. Customer churn decreased to 2.3%. New enterprise contracts: 7.",
        response="Q3 shows strong growth with 15% revenue increase to $4.2M and healthy net income of $1.1M. Customer retention improved with churn dropping to 2.3%. I recommend focusing on enterprise expansion given the 7 new contracts this quarter.",
    )
    receipt_full = generate_receipt(trace_full)
    receipt_full_dict = receipt_to_dict(receipt_full)

    # constitution_ref
    receipt_full_dict["constitution_ref"] = {
        "document_id": "test-full-agent/1.0.0",
        "policy_hash": hash_text("test-full-agent-policy-content", truncate=64),
        "version": "1.0.0",
        "source": "fixtures/constitutions/full-featured.yaml",
        "approved_by": ["test-author@sanna.dev", "test-reviewer@sanna.dev"],
        "approval_date": "2026-02-22",
        "approval_method": "dual-review",
        "signature_verified": True,
        "scheme": "constitution_sig_v1",
    }

    # enforcement (allowed)
    receipt_full_dict["enforcement"] = {
        "action": "allowed",
        "reason": "All checks passed",
        "failed_checks": [],
        "enforcement_mode": "log",
        "timestamp": receipt_full_dict["timestamp"],
    }

    # evaluation_coverage
    total_checks = len(receipt_full_dict.get("checks", []))
    evaluated = sum(1 for c in receipt_full_dict.get("checks", [])
                    if c.get("status") not in ("NOT_CHECKED", "ERRORED"))
    not_checked = total_checks - evaluated
    coverage_bp = (evaluated * 10000 // total_checks) if total_checks > 0 else 10000
    receipt_full_dict["evaluation_coverage"] = {
        "total_invariants": total_checks,
        "evaluated": evaluated,
        "not_checked": not_checked,
        "coverage_basis_points": coverage_bp,
    }

    # authority_decisions
    receipt_full_dict["authority_decisions"] = [
        {
            "action": "financial_report_read",
            "params": {"report_id": "Q3-2026"},
            "decision": "allow",
            "reason": "Action matches can_execute pattern *_read",
            "boundary_type": "can_execute",
            "escalation_target": None,
            "timestamp": receipt_full_dict["timestamp"],
        }
    ]

    # escalation_events (empty list — no escalation needed)
    receipt_full_dict["escalation_events"] = []

    # source_trust_evaluations
    receipt_full_dict["source_trust_evaluations"] = [
        {
            "source_name": "internal-database",
            "trust_tier": "tier_1",
            "evaluated_at": receipt_full_dict["timestamp"],
            "verification_flag": None,
            "context_used": True,
        }
    ]

    # extensions
    receipt_full_dict["extensions"] = {
        "com.sanna.test": {
            "fixture": True,
            "purpose": "golden-test-vector",
        }
    }

    receipt_full_dict = recompute_fingerprint(receipt_full_dict)
    receipt_full_signed = sign_receipt(receipt_full_dict, priv_key_path, "test-author@sanna.dev")

    full_path = RECEIPTS / "full-featured.json"
    full_path.write_text(json.dumps(receipt_full_signed, indent=2, ensure_ascii=False) + "\n")
    print(f"  Wrote: {full_path}")

    return {
        "pass-single-check": receipt_pass_signed,
        "fail-halted": receipt_fail_signed,
        "escalated": receipt_esc_signed,
        "full-featured": receipt_full_signed,
    }


# ── Step 4: Generate golden hashes ───────────────────────────────────

def generate_golden_hashes(receipts, key_id):
    """Compute and write golden-hashes.json."""
    print("[4/6] Computing golden hashes...")

    golden = {
        "generated_with": f"sanna v{TOOL_VERSION}",
        "spec_version": SPEC_VERSION,
        "checks_version": CHECKS_VERSION,
        "EMPTY_HASH": EMPTY_HASH,
        "test_key_id": key_id,
        "receipts": {},
    }

    for name, receipt in receipts.items():
        entry = {
            "receipt_id": receipt["receipt_id"],
            "correlation_id": receipt["correlation_id"],
            "context_hash": receipt["context_hash"],
            "output_hash": receipt["output_hash"],
            "receipt_fingerprint": receipt["receipt_fingerprint"],
            "full_fingerprint": receipt["full_fingerprint"],
            "status": receipt["status"],
            "checks_passed": receipt["checks_passed"],
            "checks_failed": receipt["checks_failed"],
        }

        if receipt.get("enforcement"):
            entry["enforcement_action"] = receipt["enforcement"]["action"]

        if receipt.get("receipt_signature"):
            entry["signature_key_id"] = receipt["receipt_signature"]["key_id"]
            entry["signature_scheme"] = receipt["receipt_signature"]["scheme"]

        if receipt.get("constitution_ref"):
            entry["constitution_policy_hash"] = receipt["constitution_ref"].get("policy_hash")

        # Canonical JSON hash (without signature) for diffing
        receipt_copy = dict(receipt)
        receipt_copy.pop("receipt_signature", None)
        entry["canonical_json_sha256"] = hash_text(
            canonical_json_bytes(sanitize_for_signing(receipt_copy)).decode("utf-8"),
            truncate=64,
        )

        golden["receipts"][name] = entry

    # Constitution content hashes
    golden["constitutions"] = {}

    minimal_path = CONSTITUTIONS / "minimal.yaml"
    if minimal_path.exists():
        content = minimal_path.read_text()
        golden["constitutions"]["minimal"] = {
            "content_hash": hash_text(content, truncate=64),
        }

    full_path = CONSTITUTIONS / "full-featured.yaml"
    if full_path.exists():
        content = full_path.read_text()
        golden["constitutions"]["full-featured"] = {
            "content_hash": hash_text(content, truncate=64),
        }

    golden_path = FIXTURES / "golden-hashes.json"
    golden_path.write_text(json.dumps(golden, indent=2, ensure_ascii=False) + "\n")
    print(f"  Wrote: {golden_path}")

    return golden


# ── Step 5: Verify round-trip ────────────────────────────────────────

def verify_fixtures(pub_key_path):
    """Verify all generated receipts with the test public key."""
    print("[5/6] Verifying receipts...")

    receipt_files = sorted(RECEIPTS.glob("*.json"))

    all_ok = True
    for rf in receipt_files:
        result = subprocess.run(
            ["sanna", "verify", str(rf), "--public-key", pub_key_path],
            capture_output=True, text=True,
        )
        status = "OK" if result.returncode == 0 else f"FAIL (exit {result.returncode})"
        print(f"  {rf.name}: {status}")
        if result.returncode != 0:
            all_ok = False
            # Show error details
            for line in result.stdout.split("\n"):
                if "ERRORS" in line or line.strip().startswith("•"):
                    print(f"    {line.strip()}")

    return all_ok


# ── Main ─────────────────────────────────────────────────────────────

def main():
    print(f"Sanna Protocol — Golden Fixture Generator")
    print(f"Using sanna v{TOOL_VERSION}, spec v{SPEC_VERSION}\n")

    ensure_dirs()

    priv_key_path, pub_key_path, key_id = generate_test_keypair()
    create_constitutions(priv_key_path)
    receipts = generate_receipts(priv_key_path, pub_key_path, key_id)
    generate_golden_hashes(receipts, key_id)
    ok = verify_fixtures(pub_key_path)

    print(f"\n{'=' * 60}")
    if ok:
        print("All fixtures generated and verified successfully.")
    else:
        print("WARNING: Some verifications failed. Check output above.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
