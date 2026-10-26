/**
 * leakguard - Leak guard extension for pi.dev
 *
 * Inspired by [@raquezha/noleaks](https://pi.dev/packages/@raquezha/noleaks).
 *
 * Protects sensitive paths from access and redacts secrets from tool output.
 * Modes:
 *   - max: Block sensitive paths AND redact secrets from output
 *   - auto (default): Same as max but blocks silently (no confirm prompts)
 *   - basic: Allow reads but still redact secrets from output (Safe Debugging)
 *   - off: Disable all protection
 *
 * Security layers (defense-in-depth):
 *   - Symlink guard: paths are resolved to their real location before checks.
 *   - Path protection: blocks reads/writes/deletes of sensitive paths.
 *   - Secret redaction: scrubs secrets from tool output.
 *   - Obfuscation detection: NFKC normalization variance + hidden/control chars.
 *   - Shell exfiltration: env-dump, sensitive expansion, transform-smuggle,
 *     discovery/exfil combine.
 *   - Egress DLP: blocks network egress carrying inline creds / secret headers.
 *   - Universal word scan: critical utilities as arguments.
 *   - Write/edit payload scan + taint tracking.
 *   - Pre-commit/push secret scan (last line of defense).
 *   - Extensible config: allow/block paths + extra secret patterns.
 *   - Audit log: ~/.pi/agent/leakguard-audit.jsonl.
 *
 * Usage:
 *   /leakguard              - Show session statistics
 *   /leakguard mode max     - Switch to MAX mode
 *   /leakguard mode auto    - Switch to AUTO mode (MAX protection, no confirm prompts)
 *   /leakguard mode basic   - Switch to BASIC mode
 *   /leakguard mode off     - Switch to OFF mode (DANGEROUS)
 */

import { homedir } from "node:os";
import { existsSync, mkdirSync, readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { execSync } from "node:child_process";

import type {
  BashToolInput,
  ExtensionAPI,
  ExtensionContext,
  ReadToolInput,
  ToolCallEvent,
  ToolResultEvent,
  WriteToolInput,
} from "@earendil-works/pi-coding-agent";

import {
  buildConfig,
  checkBashExfil,
  checkBashWords,
  checkEgressSecrets,
  checkObfuscation,
  checkPathSensitivityExtended,
  detectGitPublish,
  hasSecretMaterial,
  isTaintedEgress,
  parseTrustedPattern,
  redactSecretsInText,
  resolvePath,
  scanForSecrets,
  describeSecretMatch,
  locateSecretMatch,
  formatAuditEntry,
  type AuditEntry,
  type LeakguardConfig,
  type RedactStats,
  type TrustedPattern,
} from "./security.js";
import {
  blockMessage,
  repeatWarning,
  redactionNote,
  remedyFor,
  searchPatternFalsePositive,
  searchPatternHint,
  REPEAT_BLOCK_THRESHOLD,
  type BlockContext,
} from "./llm-hints.js";
import { describeSecretShape, describeNote } from "./shape.js";

// ============================================================================
// Types
// ============================================================================

type Mode = "max" | "basic" | "auto" | "off";

interface SessionStats extends RedactStats {
  blockedCalls: number;
  redactedSecrets: number;
  startTime: number;
  blockedByCategory: Record<string, number>;
}

interface ExtensionState {
  mode: Mode;
  allowOnce: boolean;
  trustedPatterns: TrustedPattern[];
  taintedPaths: Set<string>;
  config: ReturnType<typeof buildConfig>;
  cwdFallback: string;
  stats: SessionStats;
  /**
   * Per-intent block counter. Keyed by tool + a coarse intent signature, and
   * reset at the end of every turn. Exists because the model cannot tell that
   * its 4th phrasing of the same operation is the same operation: in a real
   * session, `bash cat`, a heredoc, `write` with a literal, and `write` with a
   * variable each tripped a DIFFERENT layer and so looked like four unrelated
   * failures. Counting per intent turns that into one clear message.
   */
  blockAttempts: Map<string, number>;
  /** When true, redacted values are replaced by a SHAPE description instead
   * of being removed. Reveals length/charset/entropy/known-prefix, never the value. */
  describeRedactions: boolean;
}

interface ToolCallResult {
  block?: boolean;
  reason?: string;
}

// ============================================================================
// Constants
// ============================================================================

const EXTENSION_NAME = "leakguard";
const DEFAULT_MODE: Mode = "auto";

/** True for modes that apply path blocking (max and yolo). */
const isBlockMode = (m: Mode): boolean => m === "max" || m === "auto";
const STATUS_KEY = "leakguard-mode";
const CONFIG_PATH = join(homedir(), ".pi", "agent", "leakguard.json");
const AUDIT_PATH = join(homedir(), ".pi", "agent", "leakguard-audit.jsonl");

// Shell commands that read files
const FILE_READ_COMMANDS = new Set([
  "cat", "less", "more", "head", "tail", "type", "bat",
  "grep", "rg", "ag", "ack",
  "source", ".",
]);

// Shell commands that write files
const FILE_WRITE_COMMANDS = new Set([
  "tee", "cp", "copy", "mv", "move", "install",
  "touch", "truncate", "dd",
]);

// Shell commands that delete files
const FILE_DELETE_COMMANDS = new Set([
  "rm", "unlink", "shred", "srm", "del", "erase", "trash",
]);

// ============================================================================
// Utility functions
// ============================================================================

function getModeIcon(mode: Mode): string {
  switch (mode) {
    case "max": return "🔒";
    case "auto": return "🔥";
    case "basic": return "🟡";
    case "off": return "⚪";
  }
}

function getModeLabel(mode: Mode): string {
  switch (mode) {
    case "max": return "leakguard MAX";
    case "auto": return "leakguard AUTO";
    case "basic": return "leakguard BASIC";
    case "off": return "leakguard OFF";
  }
}

function extractPathsFromCommand(command: string): string[] {
  const tokenRegex = /(['"])([^'"]+)\1|(\S+)/g;
  const paths: string[] = [];
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(command)) !== null) {
    const token = match[2] ?? match[3] ?? "";
    if (token.startsWith("-")) continue;
    if (["|", "&&", "||", ">>", ">", "<", "<<", ";"].includes(token)) continue;
    paths.push(token);
  }

  return paths;
}

function getShellCommandName(command: string): string {
  const tokens = command.trim().split(/\s+/);
  for (const token of tokens) {
    if (!token.startsWith("-") && !["|", "&&", "||", ";"].includes(token)) {
      const parts = token.split("/");
      return (parts[parts.length - 1] ?? token).toLowerCase();
    }
  }
  return "";
}

// ============================================================================
// Persistence + audit (extensible config)
// ============================================================================

function loadConfig(): { mode: Mode; raw: LeakguardConfig } {
  const fallback: { mode: Mode; raw: LeakguardConfig } = { mode: DEFAULT_MODE, raw: {} };
  try {
    if (existsSync(CONFIG_PATH)) {
      const raw = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as LeakguardConfig;
      const mode = raw.mode === "max" || raw.mode === "basic" || raw.mode === "auto" || raw.mode === "off" ? raw.mode : DEFAULT_MODE;
      return { mode, raw };
    }
  } catch {
    // ignore unreadable config
  }
  return fallback;
}

function saveConfig(mode: Mode): void {
  try {
    const dir = join(homedir(), ".pi", "agent");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const existing = existsSync(CONFIG_PATH) ? JSON.parse(readFileSync(CONFIG_PATH, "utf8") as string) : {};
    writeFileSync(CONFIG_PATH, JSON.stringify({ ...existing, mode }), "utf8");
  } catch {
    // ignore unwritable config
  }
}

function audit(e: AuditEntry): void {
  try {
    const dir = join(homedir(), ".pi", "agent");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    appendFileSync(AUDIT_PATH, formatAuditEntry(e), "utf8");
  } catch {
    // ignore unwritable audit log
  }
}

// ============================================================================
// Extension
// ============================================================================

export default function leakguardPersonal(pi: ExtensionAPI): void {
  const loaded = loadConfig();
  const state: ExtensionState = {
    mode: loaded.mode,
    allowOnce: false,
    trustedPatterns: [],
    taintedPaths: new Set<string>(),
    config: buildConfig(loaded.raw),
    cwdFallback: process.cwd(),
    blockAttempts: new Map<string, number>(),
    describeRedactions: false,
    stats: {
      blockedCalls: 0,
      redactedSecrets: 0,
      startTime: Date.now(),
      blockedByCategory: {},
      redactedByPattern: {},
    },
  };

  // ──────────────────────────────────────────────────────────────────────────
  // UI helpers
  // ──────────────────────────────────────────────────────────────────────────

  const updateStatus = (ctx: ExtensionContext): void => {
    if (!ctx.hasUI) return;
    const allowOnceTag = state.allowOnce ? " ⚡" : "";
    ctx.ui.setStatus(STATUS_KEY, `${getModeIcon(state.mode)} ${getModeLabel(state.mode)}${allowOnceTag}`);
  };

  const notify = (ctx: ExtensionContext, message: string, level: "info" | "warning" | "error" = "info"): void => {
    if (!ctx.hasUI) return;
    ctx.ui.notify(message, level);
  };

  const setMode = (ctx: ExtensionContext, newMode: Mode): void => {
    state.mode = newMode;
    saveConfig(newMode);
    updateStatus(ctx);
  };

  /**
   * Ask the user before blocking. In AUTO mode, blocks silently without
   * asking (redaction still applies at tool_result). In max/basic mode,
   * shows a confirm prompt.
   *
   * `hints` carries WHAT matched and WHERE, so the block message handed back to
   * the model can name the pattern and location instead of saying "secret-looking
   * material". This is the difference between one retry and a guessing loop.
   */
  const confirmBlock = async (
    ctx: ExtensionContext,
    title: string,
    body: string,
    category: string,
    hints?: BlockContext
  ): Promise<boolean> => {
    if (state.mode === "auto") {
      recordBlock(category);
      audit({ ts: new Date().toISOString(), event: "block", tool: "confirm", category, reason: "auto silent block" });
      return false; // AUTO: block silently without asking
    }
    recordBlock(category);
    // pi's ui.confirm() only supports Yes/No (Promise<boolean>). We can't
    // add a third "auto" button; instead, surface the mode auto command in
    // the body so the user discovers it in context.
    const hint = "\n\nTip: run `/leakguard mode auto` to skip these prompts (blocks stay on, no confirm).";
    // The model sees `body` on denial. Append the actionable part there, not to
    // the prompt, so the human still reads the short version.
    const ok = await ctx.ui.confirm(title, body + hint);
    if (!ok) {
      const reason = hints
        ? `${body}\n${repeatAwareGuidance(hints)}`
        : body;
      audit({ ts: new Date().toISOString(), event: "block", tool: "confirm", category, reason: body.slice(0, 120) });
      return false; // user denied → keep blocked
    }
    unrecordBlock(category);
    audit({ ts: new Date().toISOString(), event: "allow", tool: "confirm", category, reason: "user allowed" });
    return true; // user allowed → proceed
  };

  /**
   * Coarse intent signature: the model's *goal*, not its spelling. `bash cat`
   * and a `write` with the same payload share a signature when they mention the
   * same sensitive token, so the 2nd attempt can be answered differently from
   * the 1st.
   */
  const intentSignature = (toolName: string, input: unknown): string => {
    let body = "";
    try {
      body = typeof input === "string" ? input : JSON.stringify(input ?? "");
    } catch {
      body = toolName;
    }
    const family = toolName === "write" || toolName === "edit" ? "write" : toolName;
    const touched = body.length > 4000 ? body.slice(0, 4000) : body;
    return `${family}:${touched.length}:${family === "bash" ? "shell" : "payload"}`;
  };

  const bumpAttempts = (toolName: string, input: unknown): number => {
    const key = intentSignature(toolName, input);
    const next = (state.blockAttempts.get(key) ?? 0) + 1;
    state.blockAttempts.set(key, next);
    return next;
  };

  /** Guidance appended to every denial, escalating once the loop is detected. */
  const repeatAwareGuidance = (hints: BlockContext): string => {
    const base = [blockMessage({ ...hints, attempts: 0 })]
      .filter((line) => line && line !== hints.pattern)
      .join("\n");
    if ((hints.attempts ?? 0) >= REPEAT_BLOCK_THRESHOLD) {
      return repeatWarning(hints.attempts ?? 0, hints);
    }
    return base;
  };

  const formatStats = (): string => {
    const duration = Math.floor((Date.now() - state.stats.startTime) / 1000);
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;

    const lines: string[] = [];
    lines.push(`Mode: ${getModeLabel(state.mode)}`);
    lines.push(`Session duration: ${minutes}m ${seconds}s`);
    lines.push(`Blocked tool calls: ${state.stats.blockedCalls}`);
    lines.push(`Redacted secrets: ${state.stats.redactedSecrets}`);

    if (Object.keys(state.stats.blockedByCategory).length > 0) {
      lines.push("\nBlocked by category:");
      for (const [cat, cnt] of Object.entries(state.stats.blockedByCategory)) {
        lines.push(`  ${cat}: ${cnt}`);
      }
    }

    if (Object.keys(state.stats.redactedByPattern).length > 0) {
      lines.push("\nRedacted by pattern:");
      for (const [pat, cnt] of Object.entries(state.stats.redactedByPattern)) {
        lines.push(`  ${pat}: ${cnt}`);
      }
    }

    return lines.join("\n");
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Path sensitivity checker
  // ──────────────────────────────────────────────────────────────────────────

  const recordBlock = (category: string): void => {
    state.stats.blockedCalls++;
    state.stats.blockedByCategory[category] = (state.stats.blockedByCategory[category] ?? 0) + 1;
  };

  const unrecordBlock = (category: string): void => {
    state.stats.blockedCalls--;
    const current = state.stats.blockedByCategory[category] ?? 0;
    if (current > 0) {
      state.stats.blockedByCategory[category] = current - 1;
    }
  };

  const checkSensitive = (path: string): { matched: boolean; category: string } => {
    const fullPath = resolvePath(state.cwdFallback ?? process.cwd(), path);
    const res = checkPathSensitivityExtended(fullPath, state.config.allow, state.config.block);
    return { matched: res.matched, category: res.category || "Sensitive" };
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Read guard
  // ──────────────────────────────────────────────────────────────────────────

  const guardReadPath = async (
    path: string,
    ctx: ExtensionContext
  ): Promise<ToolCallResult> => {
    const check = checkSensitive(path);

    if (!check.matched) return {};
    if (!isBlockMode(state.mode)) return {}; // basic and off: allow reads

    const ok = await confirmBlock(
      ctx,
      "⚠️ Sensitive File Access",
      `leakguard: attempt to read sensitive file:\n\n  ${path}\n\nCategory: ${check.category}\n\nAllow this read?`,
      check.category
    );

    if (!ok) {
      return {
        block: true,
        reason: `Blocked by ${EXTENSION_NAME}: read of sensitive path '${path}' (${check.category})`,
      };
    }

    // Taint tracking: remember sensitive reads
    state.taintedPaths.add(resolvePath(ctx.cwd, path));
    return {};
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Write guard (max mode only)
  // ──────────────────────────────────────────────────────────────────────────

  const guardWritePath = async (
    path: string,
    ctx: ExtensionContext
  ): Promise<ToolCallResult> => {
    const check = checkSensitive(path);

    if (!check.matched) return {};
    if (!isBlockMode(state.mode)) return {};

    const ok = await confirmBlock(
      ctx,
      "⚠️ Sensitive File Write",
      `leakguard: attempt to write to sensitive file:\n\n  ${path}\n\nCategory: ${check.category}\n\nAllow this write?`,
      check.category
    );

    if (!ok) {
      return {
        block: true,
        reason: `Blocked by ${EXTENSION_NAME}: write to sensitive path '${path}' (${check.category})`,
      };
    }
    return {};
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Bash guard
  // ──────────────────────────────────────────────────────────────────────────

  const guardBashCommand = async (
    input: BashToolInput,
    ctx: ExtensionContext
  ): Promise<ToolCallResult> => {
    const commandName = getShellCommandName(input.command);

    // Pre-commit/push secret scan (last line of defense)
    const gitPublish = detectGitPublish(input.command);
    if (gitPublish && isBlockMode(state.mode)) {
      // Scan staged + working diff for secrets.
      //
      // The pathspec used to exclude `.env*`, which meant the ONE thing a
      // pre-commit scan most needs to catch — a .env being staged — was
      // invisible to it. Verified empirically: with `:(exclude).env*` in place,
      // `git add .env && git commit` produced no finding. The exclusion is
      // dropped here; the separate path-layer guards still cover .env reads.
      let diff = "";
      let stagedEnvFiles: string[] = [];
      try {
        diff = execSync("git diff --cached -- . 2>/dev/null; git diff -- . 2>/dev/null", {
          cwd: ctx.cwd,
          encoding: "utf8",
          maxBuffer: 5 * 1024 * 1024,
        });
        const names = execSync("git diff --cached --name-only --diff-filter=ACMR 2>/dev/null", {
          cwd: ctx.cwd,
          encoding: "utf8",
        });
        stagedEnvFiles = names
          .split("\n")
          .map((s) => s.trim())
          .filter((f) => f.length > 0)
          .filter((f) => /(?:^|\/)\.env(?:\.|$)/i.test(f))
          .filter((f) => !/\.(?:example|sample|template)$/i.test(f));
      } catch {
        diff = "";
      }
      const found = scanForSecrets(diff, state.config.secretPatterns);
      if (found.length > 0 || stagedEnvFiles.length > 0) {
        const attempts = bumpAttempts("git", input.command);
        const detail = [
          ...stagedEnvFiles.map((f) => `${f} (env file)`),
          ...found,
        ].join(", ");
        const ok = await confirmBlock(
          ctx,
          "⚠️ Secret in Git Diff",
          `leakguard: ${gitPublish} would publish content containing possible secret(s):\n\n  ${detail}\n\nAllow anyway?`,
          "Git Secret",
          { tool: "git", location: gitPublish, pattern: found[0], masked: stagedEnvFiles[0], attempts }
        );
        if (!ok) {
          return {
            block: true,
            reason: [
              `leakguard blocked ${gitPublish}: ${detail}`,
              "",
              stagedEnvFiles.length > 0
                ? "An .env file must not be committed. Commit a .env.example (placeholder values) and keep the real one out of git; the runtime reads it from its own path, not from the repo."
                : remedyFor(found[0]),
            ].join("\n"),
          };
        }
      }
    }

    // Check reads
    if (FILE_READ_COMMANDS.has(commandName) && isBlockMode(state.mode)) {
      const paths = extractPathsFromCommand(input.command);
      for (const p of paths) {
        const check = checkSensitive(p);
        if (!check.matched) continue;

        const ok = await confirmBlock(
          ctx,
          "⚠️ Sensitive File Access via Shell",
          `leakguard: ${commandName} on sensitive file:\n\n  ${p}\n\nCategory: ${check.category}\n\nAllow?`,
          check.category
        );

        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: shell command '${commandName}' reads sensitive path '${p}'`,
          };
        }
        state.taintedPaths.add(resolvePath(ctx.cwd, p));
      }
    }

    // Check writes (block mode only)
    if (FILE_WRITE_COMMANDS.has(commandName) && isBlockMode(state.mode)) {
      const paths = extractPathsFromCommand(input.command);
      for (const p of paths) {
        const check = checkSensitive(p);
        if (!check.matched) continue;

        const ok = await confirmBlock(
          ctx,
          "⚠️ Sensitive File Write via Shell",
          `leakguard: ${commandName} writes to sensitive file:\n\n  ${p}\n\nCategory: ${check.category}\n\nAllow?`,
          check.category
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: shell command '${commandName}' writes to sensitive path '${p}'`,
          };
        }
      }
    }

    // Check deletes (block mode only)
    if (FILE_DELETE_COMMANDS.has(commandName) && isBlockMode(state.mode)) {
      const paths = extractPathsFromCommand(input.command);
      for (const p of paths) {
        if (p === "-rf" || p === "-f" || p === "-r" || p === "-fr") continue;

        const check = checkSensitive(p);
        if (!check.matched) continue;

        const ok = await confirmBlock(
          ctx,
          "⚠️ Sensitive File Delete",
          `leakguard: ${commandName} deletes sensitive file:\n\n  ${p}\n\nCategory: ${check.category}\n\nAllow?`,
          check.category
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: shell command '${commandName}' deletes sensitive path '${p}'`,
          };
        }
      }
    }

    // --- 2026 security layers ---
    const obfuscation = checkObfuscation(input.command);
    if (obfuscation && isBlockMode(state.mode)) {
      const ok = await confirmBlock(ctx, "⚠️ Obfuscated Command", `leakguard: ${obfuscation}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Obfuscation");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${obfuscation}` };
    }

    const egress = checkEgressSecrets(input.command);
    if (egress) {
      const ok = await confirmBlock(ctx, "⚠️ Egress DLP", `leakguard: ${egress}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Egress DLP");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${egress}` };
    }

    const exfil = checkBashExfil(input.command);
    if (exfil && (isBlockMode(state.mode) || exfil.includes("secret") || exfil.includes("environment"))) {
      const ok = await confirmBlock(ctx, "⚠️ Exfiltration Risk", `leakguard: ${exfil}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Exfiltration");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${exfil}` };
    }

    const words = checkBashWords(input.command, ctx.cwd, state.mode);
    if (words && isBlockMode(state.mode)) {
      // The highest-value false positive in practice: a sensitive token used as a
      // SEARCH PATTERN, not as a path. `grep -n 'DOTENV|\.env' file.ts` was
      // blocked as a path access, and the model then read a 583-line file
      // instead of grepping it — 5x the tokens. Detect the shape and say so
      // rather than making the model guess.
      const hit = (words.match(/'([^']+)'/)?.[1]) ?? "";
      const asPattern = hit ? searchPatternFalsePositive(input.command, hit) : undefined;
      const attempts = bumpAttempts("bash", input.command);

      if (asPattern) {
        const ok = await confirmBlock(
          ctx,
          "⚠️ Risky Command (looks like a search pattern)",
          `leakguard: ${words}\n\n${searchPatternHint(asPattern)}\n\nAllow?`,
          "Command Scan",
          { tool: "bash", location: "command argument", pattern: undefined, attempts }
        );
        if (!ok) {
          return {
            block: true,
            reason: [
              `leakguard blocked bash: ${words}`,
              "",
              searchPatternHint(asPattern),
              "",
              remedyFor(undefined),
            ].join("\n"),
          };
        }
        return {};
      }

      const ok = await confirmBlock(
        ctx,
        "⚠️ Risky Command",
        `leakguard: ${words}\n\nCommand will be blocked unless you allow it.\n\nAllow?`,
        "Command Scan",
        { tool: "bash", location: "command argument", attempts }
      );
      if (!ok) {
        return {
          block: true,
          reason: blockMessage({
            tool: "bash",
            location: `command argument (${words})`,
            attempts,
          }),
        };
      }
    }

    return {};
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Result redactor
  // ──────────────────────────────────────────────────────────────────────────

  const redactToolResult = (
    event: ToolResultEvent
  ): { content: typeof event.content; details?: Record<string, unknown> } | undefined => {
    if (state.mode === "off") return undefined;
    if (!event.content || !Array.isArray(event.content)) return undefined;

    // allow-once: skip redaction for exactly one tool_result, then reset
    if (state.allowOnce) {
      state.allowOnce = false;
      updateStatus(event as unknown as ExtensionContext);
      audit({ ts: new Date().toISOString(), event: "allow", tool: event.toolName, reason: "allow-once" });
      return {
        content: event.content,
        details: { ...(event.details as Record<string, unknown> | undefined ?? {}), leakguardAllowedOnce: true },
      };
    }

    // Build trustedTest from active trusted patterns
    const trustedTest = state.trustedPatterns.length > 0
      ? (text: string) => state.trustedPatterns.some((p) => p.test(text))
      : undefined;

    let totalRedacted = 0;
    let contentChanged = false;
    // Which rules fired, and where. The old note counted secrets but never said
    // which patterns, so the model could not tell if a redaction was even
    // relevant to its task.
    const rulesFired: string[] = [];
    // Shapes of the values redacted, collected only in describe mode. Computed
    // from the ORIGINAL text, before the placeholder replaced the value.
    const describedShapes: string[] = [];
    const beforeCounts = { ...state.stats.redactedByPattern };
    let changedIndex = -1;
    const newContent = event.content.map((block, i) => {
      if (block.type !== "text") return block;
      const textBlock = block as { type: "text"; text: string };

      if (state.describeRedactions) {
        for (const pat of state.config.secretPatterns) {
          const rx = new RegExp(pat.pattern.source, pat.pattern.flags);
          for (const m of textBlock.text.matchAll(rx)) {
            const val = m[0];
            if (val && describedShapes.length < 12) {
              describedShapes.push(`${pat.name}: ${describeSecretShape(val)}`);
            }
          }
        }
      }

      const result = redactSecretsInText(textBlock.text, state.stats, state.config.secretPatterns, {
        trustedTest,
      });
      if (result.count > 0) {
        totalRedacted += result.count;
        contentChanged = true;
        if (changedIndex === -1) changedIndex = i;
        for (const name of Object.keys(state.stats.redactedByPattern)) {
          if ((state.stats.redactedByPattern[name] ?? 0) > (beforeCounts[name] ?? 0) && !rulesFired.includes(name)) {
            rulesFired.push(name);
          }
        }
        return { ...textBlock, text: result.text };
      }
      return block;
    });

    if (contentChanged) {
      state.stats.redactedSecrets += totalRedacted;
      audit({ ts: new Date().toISOString(), event: "redact", tool: event.toolName, count: totalRedacted });

      const repeat = isRepeatRedaction(event.toolName, rulesFired);
      const note = state.describeRedactions
        ? describeNote(totalRedacted, describedShapes, rulesFired)
        : redactionNote(totalRedacted, rulesFired, repeat);
      // Attach to the block that actually changed. The old code always used
      // index 0, so a redaction landing in a later text block arrived with no
      // explanation and the model re-ran the tool to "get the real output".
      const target = changedIndex >= 0 && newContent[changedIndex]?.type === "text" ? changedIndex : 0;
      if (newContent.length > 0 && newContent[target]?.type === "text") {
        const tb = newContent[target] as { type: "text"; text: string };
        newContent[target] = { ...tb, text: note + tb.text };
      }
      return {
        content: newContent,
        details: { ...(event.details as Record<string, unknown> | undefined ?? {}), leakguardRedacted: totalRedacted },
      };
    }

    return undefined;
  };

  // cwd fallback for checkSensitive (used before ctx available in some paths)
  state.cwdFallback = process.cwd();

  // ──────────────────────────────────────────────────────────────────────────
  // Event handlers
  // ──────────────────────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    state.stats = {
      blockedCalls: 0,
      redactedSecrets: 0,
      startTime: Date.now(),
      blockedByCategory: {},
      redactedByPattern: {},
    };
    state.cwdFallback = ctx.cwd;
    updateStatus(ctx);
    notify(ctx, `🛡️ ${EXTENSION_NAME} loaded (mode: ${state.mode})`, "info");
  });

  pi.on("session_shutdown", async () => {
    // Cleanup handled by session lifecycle
  });

  pi.on("tool_call", async (event, ctx) => {
    if (state.mode === "off") return undefined;
    const e = event as ToolCallEvent;

    if (e.toolName === "bash") {
      return await guardBashCommand(e.input as BashToolInput, ctx);
    }

    if (e.toolName === "read") {
      return await guardReadPath((e.input as ReadToolInput).path, ctx);
    }

    if (e.toolName === "write" || e.toolName === "edit") {
      const writeResult = await guardWritePath((e.input as WriteToolInput).path, ctx);
      if (writeResult.block) return writeResult;
      if (isBlockMode(state.mode) && hasSecretMaterial(e.input, { path: (e.input as WriteToolInput).path })) {
        // Name the pattern and the masked line, so the model can fix it in one
        // pass instead of guessing which of 31 rules fired.
        const payloadText = (() => {
          try {
            return typeof e.input === "string" ? e.input : JSON.stringify(e.input ?? "");
          } catch {
            return "";
          }
        })();
        const pattern = describeSecretMatch(payloadText);
        const masked = locateSecretMatch(payloadText);
        const attempts = bumpAttempts(e.toolName, e.input);
        const ok = await confirmBlock(
          ctx,
          "⚠️ Secret in Write Payload",
          `leakguard: this ${e.toolName} payload contains ${pattern ? `a "${pattern}"` : "secret-looking material"}.\n\nAllow this write?`,
          "Secret Payload",
          { pattern, masked, tool: e.toolName, attempts }
        );
        if (!ok) {
          return {
            block: true,
            reason: blockMessage({
              pattern,
              masked,
              tool: e.toolName,
              location: "write payload",
              attempts,
            }),
          };
        }
      }
      if (isBlockMode(state.mode) && isTaintedEgress(e.toolName, e.input, state.taintedPaths)) {
        const ok = await confirmBlock(
          ctx,
          "⚠️ Tainted Egress",
          "leakguard: write references content previously read from a sensitive path.\n\nAllow this write?",
          "Taint Egress"
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: write references tainted sensitive content`,
          };
        }
      }
      return writeResult;
    }

    // grep / find / ls guards over sensitive paths (block mode)
    if ((e.toolName === "grep" || e.toolName === "find" || e.toolName === "ls") && isBlockMode(state.mode)) {
      const pathArg = (e.input as { path?: string }).path;
      if (pathArg) {
        const check = checkSensitive(pathArg);
        if (check.matched) {
          const ok = await confirmBlock(
            ctx,
            "⚠️ Sensitive Path Scan",
            `leakguard: ${e.toolName} over sensitive path '${pathArg}' (${check.category}).\n\nAllow?`,
            check.category
          );
          if (!ok) {
            return {
              block: true,
              reason: `Blocked by ${EXTENSION_NAME}: ${e.toolName} over sensitive path '${pathArg}' (${check.category})`,
            };
          }
        }
      }
      if (hasSecretMaterial(e.input, { path: (e.input as { path?: string }).path })) {
        const ok = await confirmBlock(
          ctx,
          "⚠️ Secret in Query",
          `leakguard: ${e.toolName} payload references secret-looking material.\n\nAllow?`,
          "Secret Payload"
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: ${e.toolName} payload references secret-looking material`,
          };
        }
      }
    }

    return undefined;
  });

  /**
   * Redaction repeat tracker. Bounded on purpose: a long session can redact
   * thousands of values, and an unbounded map would leak memory. 512 entries is
   * far more than any single turn produces.
   */
  const recentRedactions = new Set<string>();

  /** Returns true when this tool already had a value redacted this session. */
  const isRepeatRedaction = (toolName: string, rules: string[]): boolean => {
    const key = `${toolName}:${[...rules].sort().join(",")}`;
    const seen = recentRedactions.has(key);
    if (!seen) {
      if (recentRedactions.size > 512) recentRedactions.clear();
      recentRedactions.add(key);
    }
    return seen;
  };

  pi.on("agent_end", async () => {
    // Attempt counters are per-turn; a new turn means a new intent.
    state.blockAttempts.clear();
    recentRedactions.clear();
  });

  pi.on("tool_result", async (event, ctx) => {
    const result = redactToolResult(event as ToolResultEvent);
    if (result && state.mode !== "off" && ((result.details?.leakguardRedacted as number) ?? 0) > 0) {
      notify(ctx, `🛡️ leakguard: redacted ${(result.details?.leakguardRedacted as number) ?? 0} secret(s) from ${event.toolName} output`, "info");
    }
    return result as { content?: typeof event.content; details?: unknown } | undefined;
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Commands
  // ──────────────────────────────────────────────────────────────────────────

  const handleCommand = async (args: string, ctx: ExtensionContext): Promise<void> => {
    const trimmed = args.trim();

    if (trimmed === "" || trimmed === "status" || trimmed === "stats") {
      notify(ctx, formatStats(), "info");
      return;
    }

    const modeMatch = trimmed.match(/^mode\s+(max|basic|auto|off)$/i);
    if (modeMatch) {
      const newMode = modeMatch[1]!.toLowerCase() as Mode;
      setMode(ctx, newMode);

      const messages: Record<Mode, string> = {
        max: `${getModeIcon("max")} ${EXTENSION_NAME}: MAX mode - blocks sensitive paths AND redacts secrets`,
        auto: `${getModeIcon("auto")} ${EXTENSION_NAME}: AUTO mode - same as MAX, but blocks silently (no confirm prompts)`,
        basic: `${getModeIcon("basic")} ${EXTENSION_NAME}: BASIC mode - allows reads but still redacts secrets`,
        off: `${getModeIcon("off")} ${EXTENSION_NAME}: OFF mode - all protection disabled (DANGEROUS)`,
      };

      notify(ctx, messages[newMode], newMode === "off" ? "warning" : "info");
      return;
    }

    // trust: manage session-level trusted patterns (sub-commands before generic add)
    if (trimmed === "trust list") {
      if (state.trustedPatterns.length === 0) {
        notify(ctx, `📋 ${EXTENSION_NAME}: no trusted patterns active.`, "info");
        return;
      }
      const lines = state.trustedPatterns.map((p, i) => `  ${i + 1}. ${p.raw}`);
      notify(ctx, `📋 ${EXTENSION_NAME} trusted patterns:\n${lines.join("\n")}`, "info");
      return;
    }
    if (trimmed === "trust clear") {
      const count = state.trustedPatterns.length;
      state.trustedPatterns = [];
      updateStatus(ctx);
      notify(ctx, `🗑️ ${EXTENSION_NAME}: cleared ${count} trusted pattern(s).`, "info");
      return;
    }
    const trustRemoveMatch = trimmed.match(/^trust\s+remove\s+(\d+)$/);
    if (trustRemoveMatch) {
      const idx = parseInt(trustRemoveMatch[1]!, 10) - 1;
      if (idx >= 0 && idx < state.trustedPatterns.length) {
        const removed = state.trustedPatterns.splice(idx, 1)[0]!;
        updateStatus(ctx);
        notify(ctx, `🗑️ ${EXTENSION_NAME}: removed trusted pattern "${removed.raw}".`, "info");
      } else {
        notify(ctx, `❌ ${EXTENSION_NAME}: invalid index. Use "trust list" to see indexes.`, "warning");
      }
      return;
    }
    const trustMatch = trimmed.match(/^trust\s+(.+)$/);
    if (trustMatch) {
      const raw = trustMatch[1]!.trim();
      const tp = parseTrustedPattern(raw);
      state.trustedPatterns.push(tp);
      updateStatus(ctx);
      audit({ ts: new Date().toISOString(), event: "allow", tool: "trust", reason: `trust pattern: ${raw}` });
      notify(ctx, `✅ ${EXTENSION_NAME}: trusting pattern "${raw}" for this session.`, "info");
      return;
    }

    // describe: redact by SHAPE instead of removing the value. Answers "is this a"
    // "real secret or a false positive?" without revealing anything.
    if (trimmed === "describe" || trimmed === "describe on" || trimmed === "describe off") {
      const turnOn = trimmed !== "describe off" ? !state.describeRedactions : false;
      state.describeRedactions = turnOn;
      updateStatus(ctx);
      notify(
        ctx,
        turnOn
          ? "🔍 leakguard: describe mode ON — redacted values are reported by shape (length, charset, entropy, known prefix) instead of being removed."
          : "🔒 leakguard: describe mode OFF — redacted values are removed again.",
        "info"
      );
      return;
    }

    // allow-once: skip redaction for the next tool_result (single use).
    // Only the human can grant this via confirm — the LLM cannot execute
    // pi commands. Flag resets after one tool_result regardless.
    if (trimmed === "allow-once") {
      if (state.allowOnce) {
        notify(ctx, `⚡ ${EXTENSION_NAME}: allow-once already active — next redacted output will pass through.`, "info");
        return;
      }
      const ok = await ctx.ui.confirm(
        "⚡ Allow Once?",
        `${EXTENSION_NAME}: allow-once lets the next single redacted value pass through without redaction.\n\n` +
        "After that one pass, redaction resumes automatically — the mode stays unchanged.\n\n" +
        "Allow this one value to bypass redaction?"
      );
      if (!ok) {
        notify(ctx, `🔒 ${EXTENSION_NAME}: allow-once cancelled.`, "info");
        return;
      }
      state.allowOnce = true;
      updateStatus(ctx);
      notify(ctx, `⚡ ${EXTENSION_NAME}: allow-once active — next redacted output will pass through.`, "warning");
      return;
    }

    // Help
    notify(
      ctx,
      `${EXTENSION_NAME} commands:\n` +
      `  /leakguard                    - Show session statistics\n` +
      `  /leakguard mode max|basic|auto|off - Change protection mode\n
  /leakguard describe        - report redacted values by SHAPE, not value\n` +
      `  /leakguard stats              - Show session statistics (alias for /leakguard)\n` +
      `  /leakguard allow-once         - Skip redaction for one value (single use, resets after)\n` +
      `  /leakguard trust <pattern>    - Trust a pattern (literal or /regex/) for this session\n` +
      `  /leakguard trust list|clear   - List or clear trusted patterns\n` +
      `  /leakguard trust remove <n>   - Remove a trusted pattern by index`,
      "info"
    );
  };

  pi.registerCommand("leakguard", {
    description: `Manage ${EXTENSION_NAME} protection (current mode: ${state.mode})`,
    handler: handleCommand,
  });
}
