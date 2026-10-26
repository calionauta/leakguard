/**
 * core/engine-client.ts — the ONLY place that talks to the betterleaks binary.
 *
 * Before this file existed, pi-leakguard's engine.ts and the OpenCode plugin each
 * implemented their own version of the same four functions: locate the binary,
 * run a scan, parse the report, redact by value. Measured: engine.ts 349 lines,
 * plugins/opencode.ts 306 lines, with `resolveEngine`, `detectSecrets`,
 * `redactOutput` and `engineStatusLine` written twice.
 *
 * That duplication is exactly where the interesting bugs live. The egress blind
 * spot -- a secret header sent as `headers={"Authorization": "..."}`, the most
 * common way a script sends a credential -- was invisible to BOTH consumers at
 * the same time, because both reimplemented the same narrow assumption. It was
 * found once and had to be fixed twice.
 *
 * This module is host-agnostic: Node builtins only, no pi API, no OpenCode API.
 * Each host keeps its own thin hook layer (path guard, egress rule, redaction
 * call) and imports detection from here.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Locate the engine.
 *
 * Two layouts exist in practice and this bit already caused a real outage:
 * macOS keeps it at ~/.bin/betterleaks, the Linux server at ~/bin/betterleaks.
 * A consumer that assumed one made the commit gate fail closed on the server,
 * which would have blocked every commit there.
 */
export function resolveEngine(): string | undefined {
  for (const candidate of [
    join(homedir(), ".bin", "betterleaks"),
    join(homedir(), "bin", "betterleaks"),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

export const ENGINE_BIN = resolveEngine();
export const ENGINE_CFG = join(homedir(), ".config", "betterleaks", "betterleaks.toml");
export const ENGINE_VERSION_FILE = join(homedir(), ".config", "betterleaks", "VERSION");

export const REDACTION_PLACEHOLDER = "[LEAKGUARD_REDACTED]";

export interface EngineFinding {
  ruleId: string;
  /** Human label for the rule, so the model sees "GitHub PAT" not "github-pat". */
  name: string;
  /** The matched value. Never log this. */
  value: string;
}

export interface ScanResult {
  findings: EngineFinding[];
  /** Set when the engine could not be trusted: a gate must fail closed on this. */
  error?: string;
}

/** Map a betterleaks rule id to a label the model can act on. */
export function ruleName(ruleId: string): string {
  return ruleId
    .replace(/^lg-/, "")
    .replace(/-/g, " ")
    .replace(/\b([a-z])/g, (m) => m.toUpperCase());
}

interface RawFinding {
  RuleID?: string;
  Secret?: string;
}

/**
 * Run the engine over arbitrary text.
 *
 * Uses a real report file, never /dev/stdout: that path intermittently fails with
 * permission denied and the tool then exits 0 with ZERO findings, which is
 * indistinguishable from "clean". This cost several wrong conclusions while
 * evaluating the engine.
 *
 * Exit 0 = clean, exit 1 = findings. Anything else is an engine failure and is
 * reported as an error rather than read as clean -- a gate that treats a broken
 * scanner as a pass is not a gate.
 */
export function detectWithEngine(
  text: string,
  opts?: { bin?: string; cfg?: string; timeoutMs?: number },
): ScanResult {
  const bin = opts?.bin ?? ENGINE_BIN;
  const cfg = opts?.cfg ?? ENGINE_CFG;

  if (!bin || !existsSync(bin)) return { findings: [], error: "betterleaks not installed" };
  if (!existsSync(cfg)) return { findings: [], error: "betterleaks config missing" };

  let dir: string | undefined;
  try {
    dir = mkdtempSync(join(tmpdir(), "leakguard-engine-"));
    const report = join(dir, "report.json");

    let status = 0;
    try {
      execFileSync(
        bin,
        ["stdin", "--config", cfg, "--no-banner", "-f", "json", "-r", report, "--log-level", "fatal"],
        {
          input: text,
          encoding: "utf8",
          timeout: opts?.timeoutMs ?? 10_000,
          stdio: ["pipe", "pipe", "pipe"],
          maxBuffer: 32 * 1024 * 1024,
        },
      );
    } catch (err) {
      status = (err as { status?: number | null }).status ?? -1;
    }

    if (status !== 0 && status !== 1) {
      return { findings: [], error: `engine exited ${status}` };
    }

    if (!existsSync(report)) return { findings: [], error: "engine wrote no report" };

    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(report, "utf8") || "[]");
    } catch {
      return { findings: [], error: "engine report is not valid JSON" };
    }
    if (!Array.isArray(raw)) return { findings: [], error: "engine report is not an array" };

    const findings: EngineFinding[] = [];
    for (const item of raw as RawFinding[]) {
      if (typeof item?.Secret !== "string" || item.Secret.length === 0) continue;
      const ruleId = item.RuleID ?? "unknown";
      findings.push({ ruleId, name: ruleName(ruleId), value: item.Secret });
    }
    return { findings };
  } catch (err) {
    return { findings: [], error: (err as Error).message.split("\n")[0] };
  } finally {
    if (dir) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }
  }
}

/** True when the text carries something the engine considers a credential. */
export function hasSecretMaterial(text: string, opts?: { bin?: string; cfg?: string }): boolean {
  return detectWithEngine(text, opts).findings.length > 0;
}

/**
 * Replace engine-reported secret values with a labelled placeholder.
 *
 * Longest value first: a short value that happens to be a substring of a longer
 * finding (a key id inside a full credential) must not corrupt the longer one.
 */
export function redactText(
  text: string,
  findings: EngineFinding[],
): { text: string; count: number; byName: Record<string, number> } {
  const byName: Record<string, number> = {};
  let out = text;
  let count = 0;

  for (const f of [...findings].sort((a, b) => b.value.length - a.value.length)) {
    if (!f.value || !out.includes(f.value)) continue;
    const before = out;
    out = out.split(f.value).join(`${REDACTION_PLACEHOLDER} — ${f.name}`);
    if (out !== before) {
      count++;
      byName[f.name] = (byName[f.name] ?? 0) + 1;
    }
  }
  return { text: out, count, byName };
}

/** Convenience: scan then redact in one call, as a host hook usually wants. */
export function scanAndRedact(text: string): { text: string; count: number; error?: string } {
  const scan = detectWithEngine(text);
  if (scan.error) return { text, count: 0, error: scan.error };
  const r = redactText(text, scan.findings);
  return { text: r.text, count: r.count };
}

export interface EngineStatus {
  available: boolean;
  version?: string;
  pinnedVersion?: string;
  drifted: boolean;
  reason?: string;
}

/**
 * Report the engine's state. Drift is REPORTED, never corrected: the 463 default
 * rules are compiled into the 22 MB binary, so a version change IS a rule change,
 * and a scanner that swaps its own detection logic is unreviewable.
 */
export function engineStatus(): EngineStatus {
  if (!ENGINE_BIN) {
    return { available: false, drifted: false, reason: "betterleaks not installed" };
  }
  let version: string | undefined;
  try {
    const out = execFileSync(ENGINE_BIN, ["--version"], { encoding: "utf8", timeout: 5_000 });
    version = out.match(/(\d+\.\d+\.\d+)/)?.[1];
  } catch {
    return { available: false, drifted: false, reason: "betterleaks present but not runnable" };
  }
  let pinnedVersion: string | undefined;
  if (existsSync(ENGINE_VERSION_FILE)) {
    try {
      pinnedVersion = readFileSync(ENGINE_VERSION_FILE, "utf8").trim() || undefined;
    } catch {
      /* ignore */
    }
  }
  const drifted = Boolean(pinnedVersion && version && pinnedVersion !== version);
  return { available: true, version, pinnedVersion, drifted };
}

/** One line for a host to surface to a human or a model. Empty when healthy. */
export function engineStatusLine(): string {
  const st = engineStatus();
  if (!st.available) {
    return `leakguard: betterleaks ${st.reason ?? "unavailable"} — credential detection is NOT running, only path guards and the egress rule. Tell the human to run: ~/.bin/betterleaks-update`;
  }
  if (st.drifted) {
    return `leakguard: betterleaks drift (pinned ${st.pinnedVersion}, running ${st.version}) — rules are compiled into the binary, so detection differs from what was reviewed. Ask the human before updating: ~/.bin/betterleaks-update`;
  }
  return "";
}
