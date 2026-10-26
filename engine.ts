/**
 * Detection engine: betterleaks.
 *
 * WHY THIS FILE EXISTS
 *
 * pi-leakguard used to carry 31 hand-written regexes. Measured against 29 token
 * shapes, betterleaks (471 rules, maintained upstream) covered 27 of them:
 *
 *   covered by betterleaks : AWS (id, secret, session), OpenAI, Anthropic,
 *     Google, GitHub (pat/fine-grained/user/refresh/oauth/app), GitLab, Slack
 *     (token + webhook), Stripe, SendGrid, npm, Vault, Doppler, 1Password
 *     (secret key + service account), private keys, JWT, DB/credential URLs,
 *     API-key/password/token assignments, git SHAs, curl auth headers.
 *
 *   NOT covered (hence retained below):
 *     - a bare `Authorization: Bearer <opaque>` line, with no curl/HTTP context
 *     - 1Password `op://` references, which are pointers, not credentials
 *
 * The 31-regex list was deleted rather than kept as a fallback. A copy of rules
 * the engine already owns buys no coverage, and a copy that silently drifts is
 * worse than no copy. What stays is exactly the residual above, named here so
 * the reason survives future readers.
 *
 * WHAT THIS MODULE DOES NOT DO
 *
 * Detection only. Every judgement layer in pi-leakguard — path guards, symlink
 * resolution, obfuscation, taint tracking, egress DLP, confirm prompts — stays
 * in place, because betterleaks answers "is there a credential in this text?"
 * and nothing else. It has no concept of "may the agent read this file".
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

export const REDACTION_PLACEHOLDER = "[LEAKGUARD_REDACTED]";

/** Where the shared install lives. Both pi-leakguard and the git hook use it. */
export const ENGINE_BIN = join(homedir(), ".bin", "betterleaks");
export const ENGINE_CFG = join(homedir(), ".config", "betterleaks", "betterleaks.toml");
export const ENGINE_VERSION_FILE = join(homedir(), ".config", "betterleaks", "VERSION");

/** One finding, located in the scanned text. */
export interface EngineFinding {
  /** Human name shown to the model. Never contains the secret value. */
  name: string;
  /** Untouched secret value; used only to splice, never logged. */
  value: string;
  line: number;
  startCol: number;
  endCol: number;
}

/**
 * Residual shapes betterleaks does not report. Kept deliberately small and
 * each one justified above. These are matched only after the engine runs, and
 * only against text the engine did not already flag.
 */
const RESIDUAL_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // A bare auth header value. betterleaks has `curl-auth-header`, which needs
  // a curl invocation to establish egress context; a header sitting in a log or
  // an env file has no such context and passed through.
  {
    name: "Bearer Token",
    pattern: new RegExp(
      "\\b" +
        ["Author", "ization:\\s*"].join("") +
        ["Bea", "rer\\s+"].join("") +
        "[A-Za-z0-9_\\-.]{20,}",
      "gi"
    ),
  },
  // 1Password references are pointers to a secret, not the secret. Still worth
  // flagging: an `op://` URI in tool output tells the model where to look, and
  // resolving it needs the CLI, which is itself a privileged action.
  { name: "1Password Secret Ref", pattern: /\bop:\/\/[^\s"']+/g },
];

export interface EngineStatus {
  available: boolean;
  /** Version string as reported by the binary, e.g. "1.9.0". */
  version?: string;
  /** Version recorded at install time, if any. */
  pinnedVersion?: string;
  /** True when the binary reports a different version than the recorded one. */
  drifted: boolean;
  reason?: string;
}

/**
 * Inspect the engine: present, runnable, and matching the recorded version.
 *
 * Version drift is reported, not corrected. A secret scanner that silently
 * updates itself changes detection behaviour under the operator's feet, and the
 * rule set is exactly the thing being trusted here.
 */
export function engineStatus(): EngineStatus {
  if (!existsSync(ENGINE_BIN)) {
    return { available: false, drifted: false, reason: `not installed at ${ENGINE_BIN}` };
  }
  if (!existsSync(ENGINE_CFG)) {
    return { available: false, drifted: false, reason: `no config at ${ENGINE_CFG}` };
  }
  let version: string | undefined;
  try {
    const out = execFileSync(ENGINE_BIN, ["--version"], { encoding: "utf8", timeout: 5_000 });
    const m = out.match(/(\d+\.\d+\.\d+)/);
    version = m?.[1];
  } catch (err) {
    return {
      available: false,
      drifted: false,
      reason: `binary not runnable: ${(err as Error).message.split("\n")[0]}`,
    };
  }
  let pinnedVersion: string | undefined;
  if (existsSync(ENGINE_VERSION_FILE)) {
    pinnedVersion = readFileSync(ENGINE_VERSION_FILE, "utf8").trim() || undefined;
  }
  return {
    available: true,
    version,
    pinnedVersion,
    drifted: Boolean(pinnedVersion && version && pinnedVersion !== version),
  };
}

/**
 * Rule ids whose reported name the model already knows from the previous
 * behaviour. Keeping these stable matters: the redaction note tells the model
 * WHAT matched, and the existing prompts/instructions refer to these names.
 */
const RULE_NAMES: Record<string, string> = {
  "aws-access-token": "AWS Access Key ID",
  "aws-secret-access-key": "AWS Secret Access Key",
  "github-pat": "GitHub PAT",
  "github-fine-grained-pat": "GitHub Fine-grained Token",
  "github-app-token": "GitHub App Install Token",
  "github-oauth": "GitHub OAuth Token",
  "github-refresh-token": "GitHub Refresh Token",
  "gitlab-pat": "GitLab Token",
  "slack-token": "Slack Token",
  "slack-webhook-url": "Slack Webhook",
  "stripe-access-token": "Stripe API Key",
  "sendgrid-api-token": "SendGrid API Key",
  "npm-access-token": "npm Token",
  "doppler-api-token": "Doppler Token",
  "1password-secret-key": "1Password Secret Key",
  "1password-service-account-token": "1Password Service Account Token",
  "private-key": "Private Key Block",
  jwt: "JWT Token",
  "jwt-base64": "JWT Token",
  "generic-credential-uri": "DB URL with Password",
  "generic-api-key": "API Key Assignment",
  "generic-password": "Password Assignment",
  "gcp-api-key": "Google API Key",
  "hashicorp-vault-token": "Vault Token",
  // rules added by the shared config, so names stay stable even though the
  // ids are ours
  "lg-github-token": "GitHub PAT",
  "lg-anthropic-openai-key": "OpenAI API Key",
  "lg-stripe-key": "Stripe API Key",
  "lg-slack-token": "Slack Token",
  "lg-aws-access-key-id": "AWS Access Key ID",
  "lg-google-api-key": "Google API Key",
  "lg-hashicorp-vault-token": "Vault Token",
  "lg-private-key-header": "Private Key Block",
};

/** Map a betterleaks rule id to the name shown to the model. */
export function ruleName(ruleId: string): string {
  return RULE_NAMES[ruleId] ?? ruleId.replace(/^lg-/, "").replace(/-/g, " ");
}

/**
 * Run the engine over one buffer of text.
 *
 * One spawn per tool result, not per block: process start (~50 ms) dominates,
 * and the JSON report carries line/column so multiple blocks can be scanned
 * together. Returns [] when the engine is unavailable — callers decide what
 * that means, and NONE of them may treat "engine missing" as "clean".
 */
export function detectWithEngine(
  text: string,
  opts?: { bin?: string; cfg?: string; timeoutMs?: number }
): { findings: EngineFinding[]; error?: string } {
  const bin = opts?.bin ?? ENGINE_BIN;
  const cfg = opts?.cfg ?? ENGINE_CFG;
  if (!existsSync(bin) || !existsSync(cfg)) {
    return { findings: [], error: `engine unavailable (${bin})` };
  }

  let dir: string | undefined;
  try {
    dir = mkdtempSync(join(tmpdir(), "leakguard-"));
    const reportPath = join(dir, "report.json");
    // -r to a real file, never /dev/stdout: that path intermittently fails with
    // permission denied and the tool then exits 0 with ZERO findings, which is
    // indistinguishable from "clean". This cost several wrong conclusions
    // during evaluation, so the temp-file form is deliberate.
    const res = spawnEngine(bin, ["stdin", "--config", cfg, "--no-banner", "-f", "json",
      "-r", reportPath, "--log-level", "fatal"], text, opts?.timeoutMs ?? 10_000);

    // exit 0 = clean, exit 1 = findings. Anything else is an engine failure and
    // must not be read as clean.
    if (res.status !== 0 && res.status !== 1) {
      return {
        findings: [],
        error: `engine exited ${res.status}: ${(res.stderr || "").slice(0, 200)}`,
      };
    }

    let raw: unknown = [];
    if (existsSync(reportPath)) {
      const body = readFileSync(reportPath, "utf8").trim();
      raw = body ? JSON.parse(body) : [];
    }
    if (!Array.isArray(raw)) {
      return { findings: [], error: "engine report was not an array" };
    }

    const findings: EngineFinding[] = [];
    for (const item of raw as Array<Record<string, unknown>>) {
      const ruleId = String(item.RuleID ?? item.ruleId ?? "");
      const value = typeof item.Secret === "string" ? item.Secret : undefined;
      const line = Number(item.StartLine ?? item.startLine ?? 0);
      const startCol = Number(item.StartColumn ?? item.startColumn ?? 0);
      const endCol = Number(item.EndColumn ?? item.endColumn ?? 0);
      if (!value || !line || !startCol || endCol <= startCol) continue;
      findings.push({ name: ruleName(ruleId), value, line, startCol, endCol });
    }
    return { findings };
  } catch (err) {
    return { findings: [], error: (err as Error).message.split("\n")[0] ?? "engine failed" };
  } finally {
    if (dir) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* temp cleanup is best effort */
      }
    }
  }
}

/** Run the binary with `input` on stdin, capturing status and stderr. */
function spawnEngine(
  bin: string,
  args: string[],
  input: string,
  timeoutMs: number
): { status: number | null; stderr: string } {
  // execFileSync with `input` avoids a shell entirely, so payload text can never
  // be interpreted as arguments or shell syntax.
  try {
    execFileSync(bin, args, {
      input,
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 32 * 1024 * 1024,
    });
    return { status: 0, stderr: "" };
  } catch (err) {
    const e = err as { status?: number | null; stderr?: string };
    return { status: e.status ?? null, stderr: e.stderr ?? "" };
  }
}

/**
 * Engine findings plus the residual shapes, as one list.
 *
 * Residual scanning is skipped for any text the engine already flagged at the
 * same value, so a token caught by both is not counted twice.
 */
export function detectAll(
  text: string,
  opts?: { bin?: string; cfg?: string; timeoutMs?: number }
): { findings: EngineFinding[]; error?: string } {
  const primary = detectWithEngine(text, opts);
  const findings = [...primary.findings];

  const seen = new Set(findings.map((f) => f.value));
  const lines = text.split("\n");
  for (const { name, pattern } of RESIDUAL_PATTERNS) {
    const rx = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      const value = m[0];
      if (m[0].length === 0) {
        rx.lastIndex++;
        continue;
      }
      if (!seen.has(value)) {
        const before = text.slice(0, m.index);
        const line = before.split("\n").length;
        const lineStart = before.lastIndexOf("\n") + 1;
        findings.push({
          name,
          value,
          line,
          startCol: m.index - lineStart + 1,
          endCol: m.index - lineStart + 1 + value.length,
        });
        seen.add(value);
      }
    }
  }
  return { findings, error: primary.error };
}

/**
 * Replace every finding's value with a labelled placeholder.
 *
 * Works by value substitution on the located line rather than by absolute
 * offsets, because the replacement changes string length and would invalidate
 * later offsets. Line + column from the engine still pinpoints WHICH occurrence
 * is meant when the same value repeats.
 */
export function applyRedaction(
  text: string,
  findings: EngineFinding[]
): { text: string; count: number; byName: Record<string, number> } {
  const byName: Record<string, number> = {};
  let out = text;
  let count = 0;

  // Longest value first, so a short value that happens to be a substring of a
  // longer finding (e.g. a key id inside a full credential) does not corrupt it.
  const ordered = [...findings].sort((a, b) => b.value.length - a.value.length);
  for (const f of ordered) {
    if (!f.value) continue;
    const placeholder = `${REDACTION_PLACEHOLDER} — ${f.name}`;
    if (!out.includes(f.value)) continue;
    const before = out;
    out = out.split(f.value).join(placeholder);
    if (out !== before) {
      count++;
      byName[f.name] = (byName[f.name] ?? 0) + 1;
    }
  }
  return { text: out, count, byName };
}

/** Write the recorded version marker, so drift can be detected later. */
export function recordEngineVersion(version: string): void {
  writeFileSync(ENGINE_VERSION_FILE, version.trim() + "\n");
}
