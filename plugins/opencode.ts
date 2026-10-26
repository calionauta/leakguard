/**
 * leakguard for OpenCode — the same thin layer pi-leakguard uses.
 *
 * Detection is delegated to betterleaks (~/.bin/betterleaks, a single static Go
 * binary with 471 rules). This file contains NO credential patterns on purpose:
 * a copy of rules the engine already owns buys no coverage and drifts silently,
 * which is the exact mistake pi-leakguard made for months.
 *
 * What lives here is only the judgement no scanner can make:
 *   - may the agent READ this path            (path guard)
 *   - is this command EXFILTRATING            (egress check)
 *   - redact BEFORE the model sees the output (tool.execute.after)
 *
 * Install: drop in ~/.config/opencode/plugins/ (or plugins/ in a project).
 */

import { execFileSync } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"

// ─── Engine location ─────────────────────────────────────────────────────────
// Two layouts exist in practice: ~/.bin on macOS and ~/bin on the Linux server.
// Probe both; a gate that cannot find its scanner must fail closed, not open.
function resolveEngine(): string | undefined {
  for (const c of [join(homedir(), ".bin", "betterleaks"), join(homedir(), "bin", "betterleaks")]) {
    if (existsSync(c)) return c
  }
  return undefined
}

const ENGINE_BIN = resolveEngine()
const ENGINE_CFG = join(homedir(), ".config", "betterleaks", "betterleaks.toml")
const VERSION_FILE = join(homedir(), ".config", "betterleaks", "VERSION")

const PLACEHOLDER = "[LEAKGUARD_REDACTED]"

// ─── Paths that are never the agent's business ──────────────────────────────
const BLOCKED_PATHS: Array<{ name: string; test: RegExp }> = [
  { name: "SSH private key", test: /(^|\/)\.ssh\/(id_|.*_rsa|.*_ed25519|.*_ecdsa|.*_dsa)/ },
  { name: "SSH config/keys", test: /(^|\/)\.ssh\// },
  { name: "GPG keyring", test: /(^|\/)\.gnupg\// },
  { name: "env file", test: /(^|\/)\.env(\.[a-z]+)?$/ },
  { name: "AWS credentials", test: /(^|\/)\.aws\/(credentials|config)/ },
  { name: "gcloud credentials", test: /(^|\/)\.config\/gcloud\// },
  { name: "kube config", test: /(^|\/)\.kube\/config/ },
  { name: "docker credentials", test: /(^|\/)\.docker\/config\.json/ },
  { name: "netrc", test: /(^|\/)\.netrc$/ },
  { name: "npmrc", test: /(^|\/)\.npmrc$/ },
  { name: "pypirc", test: /(^|\/)\.pypirc$/ },
  { name: "git credentials", test: /(^|\/)\.git-credentials$/ },
  { name: "secrets dir", test: /(^|\/)\.secrets\// },
  { name: "pi secrets", test: /(^|\/)\.pi-secrets\// },
  { name: "system shadow", test: /^\/etc\/(shadow|sudoers|passwd)$/ },
  { name: "macOS keychain", test: /Library\/Keychains\// },
]

/** Documentation and fixtures exist to show what a credential looks like. */
function isDocumentationPath(p: string): boolean {
  return (
    /(^|\/)(docs?|examples?|fixtures?|testdata)\//.test(p) ||
    /\.(md|mdx|rst|adoc)$/.test(p) ||
    /\.(example|sample|template)(\.[^.]+)?$/.test(p)
  )
}

/** Tools whose arguments name a file the agent intends to read or write. */
const PATH_TOOLS = new Set(["read", "write", "edit", "patch", "view"])

/** Tools/commands that send data somewhere. */
const EGRESS_COMMANDS =
  /(^|[\s|;&(])(curl|wget|nc|ncat|netcat|socat|telnet|scp|rsync|ftp|lftp|ssh|httpie|http|xh)\s/

/**
 * Is this text carrying a credential?
 *
 * One engine spawn. Uses a real report file, never /dev/stdout: that path fails
 * intermittently with permission denied and the tool then exits 0 with zero
 * findings, which is indistinguishable from "clean".
 */
export function detectSecrets(text: string): { count: number; names: string[]; error?: string } {
  if (!ENGINE_BIN) return { count: 0, names: [], error: "betterleaks not installed" }
  if (!existsSync(ENGINE_CFG)) return { count: 0, names: [], error: "betterleaks config missing" }

  let dir: string | undefined
  try {
    dir = mkdtempSync(join(tmpdir(), "oc-leakguard-"))
    const report = join(dir, "r.json")
    let status = 0
    try {
      execFileSync(
        ENGINE_BIN,
        ["stdin", "--config", ENGINE_CFG, "--no-banner", "-f", "json", "-r", report, "--log-level", "fatal"],
        { input: text, encoding: "utf8", timeout: 10_000, stdio: ["pipe", "pipe", "pipe"], maxBuffer: 32 * 1024 * 1024 },
      )
    } catch (err) {
      status = (err as { status?: number | null }).status ?? 0
    }
    // exit 0 = clean, exit 1 = findings; anything else is an engine failure and
    // must never be read as clean.
    if (status !== 0 && status !== 1) return { count: 0, names: [], error: `engine exited ${status}` }

    const findings = existsSync(report) ? JSON.parse(readFileSync(report, "utf8") || "[]") : []
    if (!Array.isArray(findings)) return { count: 0, names: [], error: "engine report not an array" }
    const names = findings.map((f: { RuleID?: string }) => f.RuleID ?? "unknown")
    return { count: findings.length, names }
  } catch (err) {
    return { count: 0, names: [], error: (err as Error).message.split("\n")[0] }
  } finally {
    if (dir) {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        /* best effort */
      }
    }
  }
}

/** Replace engine-reported secret values with a labelled placeholder. */
export function redactOutput(text: string): { text: string; count: number } {
  if (!ENGINE_BIN || !existsSync(ENGINE_CFG)) return { text, count: 0 }

  let dir: string | undefined
  try {
    dir = mkdtempSync(join(tmpdir(), "oc-redact-"))
    const report = join(dir, "r.json")
    try {
      execFileSync(
        ENGINE_BIN,
        ["stdin", "--config", ENGINE_CFG, "--no-banner", "-f", "json", "-r", report, "--log-level", "fatal"],
        { input: text, encoding: "utf8", timeout: 10_000, stdio: ["pipe", "pipe", "pipe"], maxBuffer: 32 * 1024 * 1024 },
      )
    } catch {
      /* exit 1 is the findings case */
    }
    if (!existsSync(report)) return { text, count: 0 }
    const findings = JSON.parse(readFileSync(report, "utf8") || "[]")
    if (!Array.isArray(findings) || findings.length === 0) return { text, count: 0 }

    // Longest value first: a short value that is a substring of a longer finding
    // must not corrupt the longer one.
    const items = (findings as Array<{ Secret?: string; RuleID?: string }>)
      .filter((f) => typeof f.Secret === "string" && f.Secret.length > 0)
      .sort((a, b) => (b.Secret?.length ?? 0) - (a.Secret?.length ?? 0))

    let out = text
    let count = 0
    for (const f of items) {
      const value = f.Secret as string
      if (!out.includes(value)) continue
      const label = (f.RuleID ?? "secret").replace(/^lg-/, "").replace(/-/g, " ")
      out = out.split(value).join(`${PLACEHOLDER} — ${label}`)
      count++
    }
    return { text: out, count }
  } catch {
    return { text, count: 0 }
  } finally {
    if (dir) {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        /* best effort */
      }
    }
  }
}

/** Report drift without correcting it: rules are compiled into the binary. */
function engineStatusLine(): string {
  if (!ENGINE_BIN) return "betterleaks NOT FOUND — secret detection is degraded"
  if (!existsSync(VERSION_FILE)) return "betterleaks installed (no pinned version recorded)"
  try {
    const pinned = readFileSync(VERSION_FILE, "utf8").trim()
    const out = execFileSync(ENGINE_BIN, ["--version"], { encoding: "utf8", timeout: 5_000 })
    const actual = out.match(/(\d+\.\d+\.\d+)/)?.[1]
    if (pinned && actual && pinned !== actual) {
      return `betterleaks drift (pinned ${pinned}, running ${actual}) — run ~/.bin/betterleaks-update`
    }
    return `betterleaks ${actual ?? "?"}`
  } catch {
    return "betterleaks present but not runnable"
  }
}

export const Leakguard = async () => {
  const status = engineStatusLine()

  return {
    // ── Before a tool runs: path guard, then egress with a credential ────────
    "tool.execute.before": async (input: { tool: string; sessionID: string; callID: string }, output: { args: any }) => {
      const args = output.args ?? {}

      // 1. Reading a protected path
      if (PATH_TOOLS.has(input.tool)) {
        const target = String(args.filePath ?? args.path ?? args.file ?? "")
        if (target && !isDocumentationPath(target)) {
          for (const rule of BLOCKED_PATHS) {
            if (rule.test.test(target)) {
              throw new Error(
                `leakguard blocked ${input.tool} on ${rule.name}: ${target}\n` +
                  `Read it by key name, or ask the human to run /leakguard allow-once. ` +
                  `Changing the path's spelling will not change the outcome.`,
              )
            }
          }
        }
      }

      // 2. A shell command that BOTH sends data somewhere AND carries a
      //    credential. Sending alone is ordinary; a credential alone is ordinary
      //    (reading a token is not a leak). The pair is the leak.
      if (input.tool === "bash") {
        const cmd = String(args.command ?? "")
        if (cmd && EGRESS_COMMANDS.test(cmd)) {
          const found = detectSecrets(cmd)
          if (found.error) {
            throw new Error(
              `leakguard: cannot verify this command (${found.error}).\n` +
                `Refusing to run an egress command while secret detection is unavailable.`,
            )
          }
          if (found.count > 0) {
            throw new Error(
              `leakguard blocked an egress command carrying a credential (${found.names.join(", ")}).\n` +
                `The value, not the spelling, is what tripped this. Build the payload at runtime if this is a test.`,
            )
          }
        }
      }
    },

    // ── After a tool returns: redact before the model ever sees it ──────────
    "tool.execute.after": async (
      input: { tool: string; sessionID: string; callID: string; args: any },
      output: { title: string; output: string; metadata: any },
    ) => {
      if (typeof output.output !== "string" || output.output.length === 0) return
      const r = redactOutput(output.output)
      if (r.count > 0) {
        output.output = r.text
        output.title = `${output.title ?? input.tool} (${r.count} secret${r.count === 1 ? "" : "s"} redacted)`
      }
    },

    event: async ({ event }: { event: { type: string } }) => {
      // Surface engine state once, at session start, rather than failing later.
      if (event?.type === "session.created") {
        if (!ENGINE_BIN) {
          console.warn(
            `leakguard: ${status}\n  Install with ~/.bin/betterleaks-update. Path guards still apply.`,
          )
        } else if (status.includes("drift")) {
          console.warn(`leakguard: ${status}`)
        }
      }
    },
  }
}

export default { id: "leakguard", server: Leakguard }
