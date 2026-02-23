import { Command } from "commander";
import { readFileSync } from "node:fs";

export async function runInspect(
  file: string,
  options: { json?: boolean },
): Promise<void> {
  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>;
  } catch (e) {
    console.error(`Error: Invalid JSON: ${e}`);
    process.exitCode = 1;
    return;
  }

  if (options.json) {
    console.log(JSON.stringify(receipt, null, 2));
    return;
  }

  // Header
  console.log("=".repeat(60));
  console.log("SANNA RECEIPT");
  console.log("=".repeat(60));
  console.log(`  Receipt ID:    ${receipt.receipt_id ?? "N/A"}`);
  console.log(`  Correlation:   ${receipt.correlation_id ?? "N/A"}`);
  console.log(`  Timestamp:     ${receipt.timestamp ?? "N/A"}`);
  console.log(`  Tool Version:  ${receipt.tool_version ?? "N/A"}`);
  console.log(`  Spec:          ${receipt.spec_version ?? "N/A"}`);
  const fp = String(receipt.receipt_fingerprint ?? "N/A");
  console.log(`  Fingerprint:   ${fp.slice(0, 32)}...`);
  console.log();

  // Status
  const checks = (receipt.checks ?? []) as Record<string, unknown>[];
  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.filter((c) => !c.passed).length;
  console.log(`  Status:        ${receipt.status ?? "UNKNOWN"}`);
  console.log(`  Checks:        ${passed} passed, ${failed} failed`);
  console.log();

  // Checks detail
  if (checks.length > 0) {
    console.log("-".repeat(60));
    console.log("CHECKS");
    console.log("-".repeat(60));
    for (const check of checks) {
      const icon = check.passed ? "PASS" : "FAIL";
      console.log(`  [${icon}] ${check.check_id}: ${check.name ?? ""}`);
      if (check.severity) console.log(`         severity: ${check.severity}`);
      if (!check.passed && check.evidence) {
        console.log(`         evidence: ${check.evidence}`);
      }
    }
    console.log();
  }

  // Authority decisions
  const auth = receipt.authority_decisions as Record<string, unknown>[] | undefined;
  if (Array.isArray(auth) && auth.length > 0) {
    console.log("-".repeat(60));
    console.log("AUTHORITY DECISIONS");
    console.log("-".repeat(60));
    for (const d of auth) {
      console.log(`  ${d.decision}: ${d.tool_name ?? d.action ?? "?"}`);
    }
    console.log();
  }

  // Escalation events
  const esc = receipt.escalation_events as Record<string, unknown>[] | undefined;
  if (Array.isArray(esc) && esc.length > 0) {
    console.log("-".repeat(60));
    console.log("ESCALATION EVENTS");
    console.log("-".repeat(60));
    for (const e of esc) {
      console.log(`  ${e.type}: ${e.target}`);
    }
    console.log();
  }

  // Constitution reference
  const constRef = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (constRef) {
    console.log("-".repeat(60));
    console.log("CONSTITUTION");
    console.log("-".repeat(60));
    console.log(`  Document ID:   ${constRef.document_id ?? "N/A"}`);
    const ph = String(constRef.policy_hash ?? "N/A");
    console.log(`  Policy Hash:   ${ph.slice(0, 32)}...`);
    console.log(`  Version:       ${constRef.version ?? "N/A"}`);
    console.log();
  }

  // Signature
  const sig = receipt.receipt_signature as Record<string, unknown> | undefined;
  if (sig) {
    console.log("-".repeat(60));
    console.log("SIGNATURE");
    console.log("-".repeat(60));
    console.log(`  Key ID:        ${sig.key_id ?? "N/A"}`);
    console.log(`  Scheme:        ${sig.scheme ?? "N/A"}`);
    console.log(`  Signed:        ${sig.signature ? "Yes" : "No"}`);
    console.log();
  }

  // Enforcement
  const enforcement = receipt.enforcement as Record<string, unknown> | undefined;
  if (enforcement) {
    console.log("-".repeat(60));
    console.log("ENFORCEMENT");
    console.log("-".repeat(60));
    console.log(`  Action:        ${enforcement.action ?? "N/A"}`);
    console.log(`  Reason:        ${enforcement.reason ?? "N/A"}`);
    console.log(`  Failed Checks: ${JSON.stringify(enforcement.failed_checks ?? [])}`);
    console.log(`  Mode:          ${enforcement.enforcement_mode ?? "N/A"}`);
    console.log();
  }

  console.log("=".repeat(60));
}

export const inspectCommand = new Command("inspect")
  .description("Pretty-print a receipt")
  .argument("<file>", "Path to receipt JSON file")
  .option("--json", "Output raw JSON (formatted)")
  .action(async (file, opts) => {
    await runInspect(file, opts);
  });
