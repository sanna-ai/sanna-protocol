import { Command } from "commander";
import { writeFileSync, existsSync } from "node:fs";

// ── Embedded templates ───────────────────────────────────────────────

const TEMPLATES: Record<string, { description: string; content: string }> = {
  developer: {
    description: "Liberal access for development workflows",
    content: `sanna_constitution: "1.0.0"

identity:
  agent_name: "{{AGENT_NAME}}"
  domain: "{{DOMAIN}}"
  description: "{{DESCRIPTION}}"

provenance:
  authored_by: "{{AUTHOR}}"
  approved_by: "{{AUTHOR}}"
  approval_date: "{{DATE}}"
  approval_method: template-default

boundaries:
  - id: B001
    description: Agent may read, write, search, fetch, and execute shell commands autonomously
    category: scope
    severity: medium
  - id: B002
    description: Delete, send, deploy, and session-spawn operations must be escalated
    category: authorization
    severity: high
  - id: B003
    description: Credential access, sudo, and gateway operations are always prohibited
    category: safety
    severity: critical

authority_boundaries:
  can_execute:
    - "*_read"
    - "*_write"
    - "*_search"
    - "*_fetch"
    - "shell_exec"
    - "file_*"
  must_escalate:
    - condition: "Any operation that deletes data"
    - condition: "Any operation that sends data externally"
    - condition: "Any deployment operation"
  cannot_execute:
    - "*_credential*"
    - "sudo_*"
    - "gateway_*"

invariants:
  - id: INV_NO_FABRICATION
    rule: Agent must not fabricate information absent from provided context
    enforcement: halt
  - id: INV_MARK_INFERENCE
    rule: Agent must clearly mark inferences that go beyond source material
    enforcement: warn
`,
  },
  "privacy-focused": {
    description: "Read-only autonomous, all writes escalated",
    content: `sanna_constitution: "1.0.0"

identity:
  agent_name: "{{AGENT_NAME}}"
  domain: "{{DOMAIN}}"
  description: "{{DESCRIPTION}}"

provenance:
  authored_by: "{{AUTHOR}}"
  approved_by: "{{AUTHOR}}"
  approval_date: "{{DATE}}"
  approval_method: template-default

boundaries:
  - id: B001
    description: Agent may only read, search, list, and fetch data autonomously
    category: scope
    severity: high
  - id: B002
    description: All write, create, update, delete, send, and post operations must be escalated
    category: authorization
    severity: critical
  - id: B003
    description: Shell access, session spawning, and credential operations are always prohibited
    category: safety
    severity: critical

authority_boundaries:
  can_execute:
    - "*_search"
    - "*_read"
    - "*_get"
    - "*_list"
    - "*_fetch"
  must_escalate:
    - condition: "Any operation that writes, creates, updates, or deletes data"
    - condition: "Any operation that sends or posts data externally"
  cannot_execute:
    - "sessions_spawn"
    - "shell_*"
    - "*_credential*"

invariants:
  - id: INV_NO_FABRICATION
    rule: Agent must not fabricate information absent from provided context
    enforcement: halt
  - id: INV_MARK_INFERENCE
    rule: Agent must clearly mark inferences that go beyond source material
    enforcement: warn
`,
  },
  "locked-down": {
    description: "Every action requires human approval",
    content: `sanna_constitution: "1.0.0"

identity:
  agent_name: "{{AGENT_NAME}}"
  domain: "{{DOMAIN}}"
  description: "{{DESCRIPTION}}"

provenance:
  authored_by: "{{AUTHOR}}"
  approved_by: "{{AUTHOR}}"
  approval_date: "{{DATE}}"
  approval_method: template-default

boundaries:
  - id: B001
    description: No actions are permitted without human approval
    category: authorization
    severity: critical
  - id: B002
    description: Shell, session, credential, and privilege-escalation operations are always prohibited
    category: safety
    severity: critical

authority_boundaries:
  can_execute: []
  must_escalate:
    - condition: "Any action not explicitly prohibited"
  cannot_execute:
    - "sessions_spawn"
    - "shell_*"
    - "*_credential*"
    - "sudo_*"

invariants:
  - id: INV_NO_FABRICATION
    rule: Agent must not fabricate information absent from provided context
    enforcement: halt
  - id: INV_MARK_INFERENCE
    rule: Agent must clearly mark inferences that go beyond source material
    enforcement: halt
  - id: INV_NO_FALSE_CERTAINTY
    rule: Agent must not express certainty beyond what evidence supports
    enforcement: halt
`,
  },
  minimal: {
    description: "Bare minimum constitution for getting started",
    content: `sanna_constitution: "1.0.0"

identity:
  agent_name: "{{AGENT_NAME}}"
  domain: "{{DOMAIN}}"
  description: "{{DESCRIPTION}}"

provenance:
  authored_by: "{{AUTHOR}}"
  approved_by: "{{AUTHOR}}"
  approval_date: "{{DATE}}"
  approval_method: template-default

boundaries:
  - id: B001
    description: Agent operates within defined scope
    category: scope
    severity: medium

invariants:
  - id: INV_NO_FABRICATION
    rule: Agent must not fabricate information absent from provided context
    enforcement: halt
`,
  },
};

// ── Command ──────────────────────────────────────────────────────────

export async function runInit(options: {
  output?: string;
  template?: string;
  agentName?: string;
  domain?: string;
  description?: string;
  enforcement?: string;
  nonInteractive?: boolean;
}): Promise<void> {
  let template = options.template ?? "developer";
  let agentName = options.agentName ?? "my-agent";
  let domain = options.domain ?? "general";
  let description = options.description ?? "";
  const output = options.output ?? "constitution.yaml";

  if (!options.nonInteractive) {
    try {
      const prompts = (await import("prompts")).default;

      const templateChoices = Object.entries(TEMPLATES).map(([key, val]) => ({
        title: key,
        description: val.description,
        value: key,
      }));

      const responses = await prompts([
        {
          type: "select",
          name: "template",
          message: "Choose a constitution template:",
          choices: templateChoices,
          initial: 0,
        },
        {
          type: "text",
          name: "agentName",
          message: "Agent name:",
          initial: agentName,
        },
        {
          type: "text",
          name: "domain",
          message: "Domain:",
          initial: domain,
        },
        {
          type: "text",
          name: "description",
          message: "Description:",
          initial: description || "AI agent governed by the Sanna protocol",
        },
      ]);

      if (responses.template !== undefined) template = responses.template;
      if (responses.agentName) agentName = responses.agentName;
      if (responses.domain) domain = responses.domain;
      if (responses.description) description = responses.description;
    } catch {
      // If prompts fails (non-interactive env), use defaults
    }
  }

  if (existsSync(output)) {
    console.error(`Error: File already exists: ${output}`);
    console.error("Remove it first or choose a different output path with --output.");
    process.exitCode = 1;
    return;
  }

  const tmpl = TEMPLATES[template];
  if (!tmpl) {
    console.error(`Error: Unknown template: ${template}`);
    console.error(`Available: ${Object.keys(TEMPLATES).join(", ")}`);
    process.exitCode = 1;
    return;
  }

  const date = new Date().toISOString().split("T")[0];
  const content = tmpl.content
    .replace(/\{\{AGENT_NAME\}\}/g, agentName)
    .replace(/\{\{DOMAIN\}\}/g, domain)
    .replace(/\{\{DESCRIPTION\}\}/g, description || `${agentName} governed by Sanna protocol`)
    .replace(/\{\{AUTHOR\}\}/g, `${agentName}@sanna.dev`)
    .replace(/\{\{DATE\}\}/g, date);

  writeFileSync(output, content, "utf-8");
  console.log(`Created ${output} (template: ${template})`);
  console.log();
  console.log("Next steps:");
  console.log(`  1. Edit ${output} with your agent's boundaries`);
  console.log("  2. Generate a signing key: sanna keygen");
  console.log(`  3. Sign it: sanna sign ${output} --private-key <key-path>`);
}

export const initCommand = new Command("init")
  .description("Create a new constitution from a template")
  .option("-o, --output <path>", "Output file path", "constitution.yaml")
  .option("-t, --template <name>", "Template name (developer, privacy-focused, locked-down, minimal)")
  .option("--agent-name <name>", "Agent name")
  .option("--domain <domain>", "Agent domain")
  .option("--description <desc>", "Agent description")
  .option("--non-interactive", "Skip interactive prompts")
  .action(async (opts) => {
    await runInit({
      output: opts.output,
      template: opts.template,
      agentName: opts.agentName,
      domain: opts.domain,
      description: opts.description,
      nonInteractive: opts.nonInteractive,
    });
  });
