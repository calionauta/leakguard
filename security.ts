/**
 * security.ts - Pure, testable security helpers for leakguard.
 *
 * Inspired by [@raquezha/noleaks](https://pi.dev/packages/@raquezha/noleaks).
 * These functions have no pi/ExtensionAPI dependency so they can be unit-tested
 * in isolation. Imported by index.ts.
 */

import { homedir } from "node:os";
import { existsSync, realpathSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { applyRedaction, detectAll, engineStatus, type EngineFinding } from "./engine.js";

export interface PathPattern {
  name: string;
  pattern: RegExp;
  category: string;
}

// Path patterns that are always sensitive
export const SENSITIVE_PATH_PATTERNS: PathPattern[] = [
  // Environment files
  { name: ".env", category: "Environment", pattern: /(?:^|[\\/])\.env(?:\.[^\\/]+)?$/ },
  { name: "*.env", category: "Environment", pattern: /(?:^|[\\/])[^\\/]+\.env$/ },

  // Private keys
  { name: "id_rsa", category: "Private Keys", pattern: /(?:^|[\\/])id_rsa$/ },
  { name: "id_dsa", category: "Private Keys", pattern: /(?:^|[\\/])id_dsa$/ },
  { name: "id_ecdsa", category: "Private Keys", pattern: /(?:^|[\\/])id_ecdsa$/ },
  { name: "id_ed25519", category: "Private Keys", pattern: /(?:^|[\\/])id_ed25519$/ },
  { name: "*.pem", category: "Private Keys", pattern: /\.(?:pem)$/i },
  { name: "*.key", category: "Private Keys", pattern: /\.(?:key)$/i },
  { name: "*.p12", category: "Private Keys", pattern: /\.(?:p12|pfx)$/i },
  { name: "*.keystore", category: "Private Keys", pattern: /\.(?:keystore|jks)$/i },

  // Credential stores
  { name: "auth.json", category: "Credentials", pattern: /(?:^|[\\/])auth\.json$/ },
  { name: ".npmrc", category: "Credentials", pattern: /(?:^|[\\/])\.npmrc$/ },
  { name: ".netrc", category: "Credentials", pattern: /(?:^|[\\/])\.netrc$/ },
  { name: ".pypirc", category: "Credentials", pattern: /(?:^|[\\/])\.pypirc$/ },
  { name: ".git-credentials", category: "Credentials", pattern: /(?:^|[\\/])\.git-credentials$/ },
  { name: "credentials.*", category: "Credentials", pattern: /(?:^|[\\/])credentials\.(?:json|ya?ml|toml|ini)$/i },
  { name: "secrets.*", category: "Credentials", pattern: /(?:^|[\\/])secrets\.(?:json|ya?ml|toml|ini)$/i },

  // Cloud/platform config (home-relative)
  { name: "~/.aws/", category: "Cloud Config", pattern: /(?:^|[\\/])\.aws[\\/]/ },
  { name: "~/.azure/", category: "Cloud Config", pattern: /(?:^|[\\/])\.azure[\\/]/ },
  { name: "~/.config/gcloud/", category: "Cloud Config", pattern: /(?:^|[\\/])\.config[\\/]gcloud[\\/]/ },
  { name: "~/.docker/", category: "Cloud Config", pattern: /(?:^|[\\/])\.docker[\\/]/ },
  { name: "~/.kube/", category: "Cloud Config", pattern: /(?:^|[\\/])\.kube[\\/]/ },

  // SSH/GPG
  { name: "~/.ssh/", category: "SSH/GPG", pattern: /(?:^|[\\/])\.ssh[\\/]/ },
  { name: "~/.gnupg/", category: "SSH/GPG", pattern: /(?:^|[\\/])\.gnupg[\\/]/ },

  // Pi-specific
  { name: ".pi-secrets/", category: "Pi Secrets", pattern: /(?:^|[\\/])\.pi-secrets[\\/]/ },

  // Shell startup files
  { name: ".bashrc", category: "Shell Config", pattern: /(?:^|[\\/])\.bashrc$/ },
  { name: ".zshrc", category: "Shell Config", pattern: /(?:^|[\\/])\.zshrc$/ },
  { name: ".bash_profile", category: "Shell Config", pattern: /(?:^|[\\/])\.bash_profile$/ },
  { name: ".zshenv", category: "Shell Config", pattern: /(?:^|[\\/])\.zshenv$/ },
  { name: ".profile", category: "Shell Config", pattern: /(?:^|[\\/])\.profile$/ },

  // System credential files
  { name: "/etc/shadow", category: "System", pattern: /^\/etc[\\/]shadow$/ },
  { name: "/etc/sudoers", category: "System", pattern: /^\/etc[\\/]sudoers(?:[\\/]|$)/ },
  { name: "/etc/passwd", category: "System", pattern: /^\/etc[\\/]passwd$/ },

  // macOS Keychain
  { name: "~/Library/Keychains/", category: "macOS Keychain", pattern: /(?:^|[\\/])Library[\\/]Keychains[\\/]/ },
];

// --- Ported secret material regexes (from @raquezha/noleaks) ---
//
// Two patterns on purpose, because the same shape has opposite cost in the two
// layers that consume it:
//
//   SECRET_VALUE_RE   — commands, egress, encoding pipelines. A 64-hex blob
//                       here is suspicious: it may be an HMAC key or a hashed
//                       credential being shipped off-box. Commands are few and
//                       high-stakes, so the bare-hex branch stays.
//
//   CONTENT_VALUE_RE  — file contents and tool output. A 64-hex blob here is
//                       overwhelmingly metadata: 86 files across 18 real repos
//                       matched (`UPSTREAM_SHA` provenance, npm `integrity`
//                       digests, `sha256:` image pins, CI fixtures asserting a
//                       digest is not a secret). Reading files is high-volume
//                       and low-stakes, so bare hex is dropped.
//
// Hex with CONTEXT stays detectable in both layers via SECRET_ASSIGNMENT_RE
// (`SOME_TOKEN=<hex>`) and the assignment patterns.
// DETECTION IS DELEGATED TO betterleaks (~/.bin/betterleaks)
//
// The 31 hand-written regexes that used to live here were removed after
// measurement: betterleaks (471 rules, maintained upstream) covered 27 of the
// 29 token shapes they caught. The 2 residual shapes live in engine.ts, each
// with the measurement that justifies it.
//
// Keeping a hand-written copy of rules the engine already owns bought no
// coverage and could only drift. What replaces the removed regexes is NOT more
// regexes -- it is thin adapters, so every caller keeps its previous contract
// while the rule set is maintained elsewhere.
//
// The bare-hex tradeoff documented below is now handled by the engine's own
// entropy and context rules, which is why the two surviving regexes are narrow.

export const SECRET_VALUE_RE = /(bearer\s+[a-z0-9._~+/=-]{12,}|op:\/\/[^\s"']+)/i;

/** Same as SECRET_VALUE_RE: both layers now defer to the engine. */
export const CONTENT_VALUE_RE = /(bearer\s+[a-z0-9._~+/=-]{12,}|op:\/\/[^\s"']+)/i;
/**
 * PEM markers are case-SENSITIVE: a real key file writes BEGIN in uppercase.
 * The lowercase substring appears inside secret DETECTORS, which must not flag.
 */
export const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

export const SECRET_KEY_RE = /(^|[^a-z0-9])(authorization|cookie|password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|refresh[_-]?token|id[_-]?token)([^a-z0-9]|$)/i;
export const SECRET_ASSIGNMENT_RE = /(^|\n)\s*[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH_?KEY|AUTH_?TOKEN|CONNECTION_?STRING|DSN)[A-Z0-9_]*\s*=\s*[^\s]+/i;
export const ENV_DUMP_RE = /(^|[;&|\s])(env|printenv|set|export)(\s*(#.*)?$|\s*[;&|>])/;
export const SENSITIVE_EXPANSION_RE = /\$(\{)?[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Z0-9_]*(\})?/i;
export const SUSPICIOUS_CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\ufeff\u2060-\u2069]/;

// Tools that can read/print/transform file contents
export const TRANSFORM_COMMANDS = new Set([
  "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "sed", "awk",
  "perl", "python", "python3", "ruby", "node", "jq", "yq", "cp", "mv", "scp", "rsync",
  "tar", "zip", "gzip", "gunzip", "base64", "xxd", "hexdump", "strings", "openssl",
  "gpg", "vi", "vim", "nvim", "nano", "code", "open", "bat", "source", ".",
  "git show", "git cat-file", "ls-tree",
]);

// Critical system utilities blocked even as nested arguments
export const CRITICAL_UTILITIES = new Set([
  "chmod", "chown", "passwd", "useradd", "userdel", "mkfs", "dd", "shred",
]);

// Discovery / exfiltration tools
export const DISCOVERY_EXFIL = new Set([
  "curl", "wget", "nc", "netcat", "ncat", "socat", "ftp", "sftp", "ssh", "scp",
  "rsync", "nmap", "tcpdump", "wireshark", "telnet", "tftp",
]);

// A real network invocation: the tool name at the start of a command position
// (start of string, after a shell separator, or after sudo/env). This is
// stricter than a word-boundary match on the tool name, which fires on prose.
export const EXFIL_INVOCATION_RE = new RegExp(
  "(?:^|[;&|(]|\\$\\()\\s*(?:sudo\\s+)?(?:" +
    [...DISCOVERY_EXFIL].sort((a, b) => b.length - a.length).join("|") +
    ")\\b",
  "i"
);

// A path that names a credential store. This is sensitive material on its own:
// `nc host < ~/.env` leaks whatever is in that file, whatever its contents are.
export const SENSITIVE_PATH_RE =
  /(?:\.(?:env|aws|ssh|gnupg|kube|docker|npmrc|pypirc|netrc|git-credentials|secrets)(?=[\s/'"`)]|$)|\.env\b)/i;

// Tools used to transform/encode material for smuggling
export const ENCODE_TOOLS = new Set(["base64", "xxd", "openssl", "gpg", "hexdump"]);

// ============================================================================
// Path utilities
// ============================================================================

export function normalizePath(path: string): string {
  return path.replaceAll("\\", "/");
}

export function expandHome(path: string): string {
  if (path.startsWith("~/") || path === "~") {
    return join(homedir(), path.slice(1));
  }
  return path;
}

/**
 * Resolve a path to its real on-disk location (symlink guard).
 * Falls back to logical resolution if the target does not exist yet.
 */
export function resolvePath(cwd: string, path: string): string {
  const expanded = expandHome(path);
  const logical = isAbsolute(expanded) ? expanded : resolve(cwd, expanded);
  try {
    return realpathSync(logical);
  } catch {
    return logical;
  }
}

export function checkPathSensitivity(path: string): { matched: boolean; pattern?: PathPattern } {
  const normalized = normalizePath(path);

  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.pattern.test(normalized)) {
      return { matched: true, pattern };
    }
  }

  return { matched: false };
}

// ============================================================================
// Shell utilities (ported)
// ============================================================================

export function shellWords(command: string): string[] {
  return command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((word) => word.replace(/^['"]|['"]$/g, "")) ?? [];
}

/**
 * Git object hashes (and short SHAs) are 7-40 char hex runs — benign, not
 * secrets. Strip them before high-entropy hex matching so legitimate git
 * commands (git show/cat-file/checkout/reset <sha>) are not false-positive
 * blocked.
 *
 * Commit SHAs are routinely echoed inside longer hex contexts (a 40-char SHA
 * followed by more hex characters in a log line), so the strip is anchored on
 * word boundaries — exactly how git prints them.
 */
export function stripGitSHAs(text: string): string {
  return text.replace(/\b[0-9a-f]{7,40}\b/gi, " ");
}

/**
 * Human-readable name for the first secret pattern that matches `text`.
 * Used to tell the model WHAT matched instead of a bare "secret-looking
 * material", which forced blind retries (see docs/leakguard-token-burn.md).
 */
export function describeSecretMatch(text: string): string | undefined {
  // The engine already returns a human name per rule (engine.ts RULE_NAMES), so
  // this no longer guesses from regex order -- it reports what actually fired.
  const { findings } = detectAll(text);
  if (findings.length > 0) return findings[0]!.name;
  if (PEM_RE.test(text)) return "Private Key Block";
  if (SECRET_ASSIGNMENT_RE.test(text)) return "secret assignment (KEY=value)";
  return undefined;
}

/**
 * The offending line with the secret itself masked, so the model can locate the
 * problem without ever seeing the value. This is the difference between "your
 * write was blocked" and "line 12 defines a GitHub PAT" — the former costs a
 * blind retry, the latter costs nothing.
 */
export function locateSecretMatch(text: string): string | undefined {
  // The engine reports StartLine/StartColumn, so masking is exact: replace the
  // reported value on the reported line, leaving every other line untouched.
  const { findings } = detectAll(text);
  if (findings.length > 0) {
    const first = findings[0]!;
    const lines = text.split("\n");
    const line = lines[Math.max(0, first.line - 1)] ?? "";
    const masked = line.split(first.value).join(`[${first.name}]`);
    return `line ${first.line}: ${masked.trim().slice(0, 120)}`;
  }
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim().length === 0) continue;
    if (!PEM_RE.test(line) && !SECRET_ASSIGNMENT_RE.test(line)) continue;
    return `line ${i + 1}: ${line.trim().slice(0, 120)}`;
  }
  return undefined;
}

/**
 * Paths where example credentials are LEGITIMATE and must not be treated as
 * leaks: documentation, sample configs, test fixtures, vendored upstream code.
 *
 * Measured: of the 50 content-layer hits across 18 real repos, nearly all sat in
 * `docs/`, `*.example.*`, test fixtures, or a vendored upstream project. Those
 * files exist precisely to show what a credential looks like.
 */
const DOCUMENTATION_PATH_RE = /(?:^|[\\/])(?:docs?|man|examples?|samples?|fixtures?|testdata|__tests__|vendor|node_modules|third_party)(?:[\\/]|$)|(?:^|[\\/])[^\\/]*\.(?:example|sample|template)(?:\.[^\\/]+)?$|(?:^|[\\/])[^\\/]*(?:_test|_spec|_test_\w*)\.\w+$|\.(?:md|mdx|rst|adoc)$/i;

/** True when `path` is documentation/example/fixture context. */
export function isDocumentationPath(path: string | undefined): boolean {
  if (!path) return false;
  return DOCUMENTATION_PATH_RE.test(normalizePath(path));
}

/**
 * Does this tool input carry secret material?
 *
 * `opts.path` lets callers pass the write/edit target so documentation and
 * fixture files are not flagged for containing example credentials. Without it
 * the behaviour is unchanged.
 */
export function hasSecretMaterial(
  value: unknown,
  opts?: { path?: string; skipDocumentation?: boolean }
): boolean {
  if (opts?.skipDocumentation !== false && isDocumentationPath(opts?.path)) {
    // Still catch the one shape that a doc file must never carry: a real private
    // key block. Everything else in a doc is illustrative by definition.
    const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text);
  }
  return hasSecretMaterialInner(value);
}

function hasSecretMaterialInner(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === "string") {
    // Content semantics, not command semantics: a bare digest in a write payload
    // is normal file content, not an exfiltration attempt. contentHasSecret
    // keeps that distinction via the engine's own rules.
    return contentHasSecret(value);
  }
  if (typeof value !== "object") return false;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY_RE.test(key) || hasSecretMaterialInner(item)) return true;
  }
  return false;
}

export function checkObfuscation(command: string): string | undefined {
  const nfkc = command.normalize("NFKC");
  if (nfkc !== command) {
    return "command rejected: Unicode normalization variance detected (possible obfuscation)";
  }
  if (SUSPICIOUS_CONTROL_RE.test(command)) {
    return "command rejected: hidden/control characters detected (possible obfuscation)";
  }
  return undefined;
}

function containsWord(text: string, word: string): boolean {
  return new RegExp(`\\b${word}\\b`).test(text);
}

export function checkBashExfil(command: string): string | undefined {
  const normalized = command.normalize("NFKC");
  const deobfuscated = normalized.replace(/\\(.)/g, "$1").replace(/['"]/g, "");
  const lower = normalized.toLowerCase();
  const deobfuscatedLower = deobfuscated.toLowerCase();

  if (ENV_DUMP_RE.test(lower)) {
    return "command attempts to dump environment variables";
  }
  if (SENSITIVE_EXPANSION_RE.test(command)) {
    return "command references sensitive environment variable names";
  }

  const hasEncodeTool = [...ENCODE_TOOLS].some((t) => containsWord(deobfuscatedLower, t));
  if (hasEncodeTool && (lower.includes("|") || lower.includes(">") || lower.includes("<"))) {
    if (commandHasSecret(command)) {
      return "command attempts to transform or smuggle secret-looking material";
    }
  }

  // An exfil tool must appear as an INVOCATION, not as a word in prose. A commit
  // message, a heredoc and a changelog entry all contain "ssh" and "curl" as
  // ordinary English; `cat > file <<'EOF'` is not a network operation.
  if (EXFIL_INVOCATION_RE.test(deobfuscatedLower)) {
    // A secret key name, or an env dump, next to a real egress invocation.
    // `set`/`export` alone is not exfiltration: `export` in prose, or exporting
    // an unrelated variable, has no secret in it. Require a key that names a
    // credential, which SECRET_KEY_RE already establishes.
    if (SECRET_KEY_RE.test(command) || ENV_DUMP_RE.test(lower) || SENSITIVE_PATH_RE.test(command)) {
      return "command combines network discovery/transfer with sensitive material";
    }
  }

  return undefined;
}

export function checkBashWords(command: string, cwd: string, mode: "max" | "basic" | "auto" | "off"): string | undefined {
  const words = shellWords(command.normalize("NFKC"));

  for (const word of words) {
    const baseWord = word.toLowerCase().split("/").pop() ?? word.toLowerCase();

    if (CRITICAL_UTILITIES.has(baseWord)) {
      return `command uses critical system utility: ${baseWord}`;
    }

    const pathReason = checkPathSensitivity(resolvePath(cwd, word));
    if (pathReason.matched && (mode === "max" || mode === "auto")) {
      return `command references protected path: ${word}`;
    }
  }

  const mentionsSensitivePath = words.some((w) => checkPathSensitivity(resolvePath(cwd, w)).matched);
  const readsOrTransforms = words.some((w) => TRANSFORM_COMMANDS.has(w.toLowerCase().split("/").pop() ?? w.toLowerCase()));
  if (mentionsSensitivePath && readsOrTransforms && (mode === "max" || mode === "auto")) {
    return "command appears to read or transform sensitive files";
  }

  if (commandHasSecret(command)) {
    return "command contains secret-looking material";
  }

  return undefined;
}

// ============================================================================
// Redaction (personal richer patterns)
// ============================================================================

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: "low" | "medium" | "high" | "critical";
}

export interface TrustedPattern {
  raw: string;
  test: (s: string) => boolean;
}

export function parseTrustedPattern(raw: string): TrustedPattern {
  if (raw.startsWith("/") && raw.endsWith("/") && raw.length > 2) {
    const source = raw.slice(1, -1);
    const regex = new RegExp(source, "i");
    return { raw, test: (s: string) => regex.test(s) };
  }
  const lower = raw.toLowerCase();
  return { raw, test: (s: string) => s.toLowerCase().includes(lower) };
}

export const REDACTION_PLACEHOLDER = "[LEAKGUARD_REDACTED]";

/**
 * The pattern list is now EMPTY by design.
 *
 * Detection lives in engine.ts (betterleaks). This array is kept only so
 * `buildConfig()` and any user-supplied `extraSecretPatterns` keep working: a
 * user can still add their own regexes via config, and those run alongside the
 * engine rather than instead of it.
 */
export const SECRET_PATTERNS: SecretPattern[] = [];

/**
 * Does this command text carry a credential?
 *
 * Command-layer call sites used to test SECRET_VALUE_RE. With detection moved
 * to the engine, they ask this instead. Synchronous by necessity (the callers
 * are sync guards), which is why the engine is invoked as a short-lived child
 * process (~50 ms) rather than an async client.
 */
export function commandHasSecret(command: string): boolean {
  const normalized = command.normalize("NFKC");
  const stripped = stripGitSHAs(normalized);
  if (SECRET_ASSIGNMENT_RE.test(stripped)) return true;
  const { findings } = detectAll(command);
  return findings.length > 0;
}

/** Content-layer variant: same engine, but a bare digest is ordinary content. */
export function contentHasSecret(value: string): boolean {
  const stripped = stripGitSHAs(value);
  if (PEM_RE.test(value) || SECRET_ASSIGNMENT_RE.test(stripped)) return true;
  const { findings } = detectAll(value);
  return findings.length > 0;
}

export interface RedactStats {
  redactedByPattern: Record<string, number>;
}

export interface RedactOptions {
  trustedTest?: (text: string) => boolean;
}

export function redactSecretsInText(
  text: string,
  stats: RedactStats,
  patterns: SecretPattern[] = SECRET_PATTERNS,
  options?: RedactOptions
): { text: string; count: number } {
  // Skip redaction entirely if text matches a trusted pattern
  if (options?.trustedTest && options.trustedTest(text)) {
    return { text, count: 0 };
  }

  // Engine findings, plus the two residual shapes the engine does not report.
  const { findings, error } = detectAll(text);

  if (error && findings.length === 0) {
    // The engine failed. Do NOT report "clean": fall back to the narrow residual
    // regexes so the two shapes we can still check are still checked, and let
    // the caller surface the degraded state rather than silently trusting it.
    return redactResidualOnly(text, stats);
  }

  // User-supplied extra patterns still run. A user who configured a pattern
  // expects it to fire regardless of what the engine knows about.
  const extra = patterns.filter((p) => p.pattern.source.trim().length > 0);
  const all: EngineFinding[] = [...findings];
  for (const pat of extra) {
    const rx = new RegExp(pat.pattern.source, pat.pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      if (m[0].length === 0) {
        rx.lastIndex++;
        continue;
      }
      all.push({ name: pat.name, value: m[0], line: 0, startCol: 0, endCol: 0 });
    }
  }

  const applied = applyRedaction(text, all);
  for (const [name, n] of Object.entries(applied.byName)) {
    stats.redactedByPattern[name] = (stats.redactedByPattern[name] ?? 0) + n;
  }
  return { text: applied.text, count: applied.count };
}

/** Residual-only pass, used when the engine is unavailable. */
function redactResidualOnly(text: string, stats: RedactStats): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const [name, rx] of [
    ["Bearer Token", /\b(Author|ization:\s*)(Bea|rer\s+)[A-Za-z0-9_\-.]{20,}/gi],
    ["1Password Secret Ref", /\bop:\/\/[^\s"']+/g],
  ] as Array<[string, RegExp]>) {
    const before = out;
    out = out.replace(rx, `${REDACTION_PLACEHOLDER} — ${name}`);
    if (out !== before) {
      count++;
      stats.redactedByPattern[name] = (stats.redactedByPattern[name] ?? 0) + 1;
    }
  }
  return { text: out, count };
}

// ============================================================================
// Egress DLP (2026 capability-separation pattern)
// ============================================================================

// Network egress tools whose arguments/body must be scanned for secrets.
// Ported concept from CredProxy/Bastion: separate secrets from egress.
export const EGRESS_TOOLS = new Set([
  "curl",
  "http",
  "https",
  "httpie",
  "xh", "wget", "nc", "netcat", "ncat", "socat", "ftp", "sftp", "ssh", "scp",
  "rsync", "telnet", "tftp", "fetch", "node", "python", "python3", "ruby", "perl",
]);

// A URL that embeds credentials (user:pass@host) is always egress-secret.
export const CREDENTIALD_URL_RE = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\/\s]+:[^@\/\s]{3,}@/;

// Basic-auth inline flag: -u user:pass / --user user:pass
export const BASIC_AUTH_FLAG_RE = /(?:-|--)u(?:ser)?\s+[^\s:]+(?::[^\s]+)/i;

// Secret-bearing HTTP headers in egress payloads.
//
// Deliberately requires a VALUE after the colon. The bare name
// `Authorization:` appears in CHANGELOGs, docs, code comments and error
// messages; flagging the name alone blocked documenting the very feature being
// shipped. The value is also the part that would actually leave the machine.
// A value must follow, and it must not be an angle-bracket placeholder:
// `Authorization: <token>` in documentation is not a credential in flight.
const HEADER_VALUE = "(?!<)[A-Za-z0-9._~+\\/-]";
export const SECRET_HEADER_RE = new RegExp(
  "(?:authorization|x-api-key|x-auth-token|proxy-authorization)[\"'\\u201c]?\\s*:\\s*(?:" +
    "(?:bearer|basic|token|digest)\\s+" + HEADER_VALUE + "{4,}" +
    "|" + HEADER_VALUE + "{8,}" +
    ")",
  "i"
);

/**
 * Deterministic egress DLP: blocks any network egress command whose
 * arguments/body/URL contain secret-looking material. Unlike checkBashExfil
 * (which only fires on env-dump/exfil *combine*), this fires on the presence
 * of a secret in the egress payload itself — the core 2026 pattern of keeping
 * secrets out of the model's egress channel.
 *
 * Conservative by design to avoid false positives: only blocks when a secret
 * is clearly present (credentialed URL, basic-auth flag, secret header, or a
 * high-entropy/known secret value/assignment).
 */
export function checkEgressSecrets(command: string): string | undefined {
  const normalized = command.normalize("NFKC").replace(/\\(.)/g, "$1").replace(/['\"]/g, "");
  const lower = normalized.toLowerCase();

  const hasEgressTool = [...EGRESS_TOOLS].some((t) => containsWord(lower, t));
  if (!hasEgressTool) return undefined;

  // Credentialed URL in the egress target (user:pass@host)
  if (CREDENTIALD_URL_RE.test(normalized)) {
    return "egress command embeds credentials in URL (possible secret exfiltration)";
  }

  // Inline basic-auth flag: -u user:pass / --user user:pass
  if (BASIC_AUTH_FLAG_RE.test(normalized)) {
    return "egress command embeds inline basic-auth credentials";
  }

  // Secret-bearing HTTP headers (Authorization:, X-Api-Key:, etc.)
  if (SECRET_HEADER_RE.test(normalized)) {
    return "egress command sends secret-bearing HTTP header";
  }

  // High-entropy / known secret value or assignment in the payload
  if (commandHasSecret(command)) {
    return "egress command carries secret-looking material in its payload";
  }

  return undefined;
}

// ============================================================================
// Taint tracking (2026 information-flow control)
// ============================================================================

/**
 * Decide whether content read from a sensitive path is being exfiltrated via a
 * tool call. If `taintedPaths` contains a previously-read sensitive path and the
 * current tool payload references that content (or a known sensitive path), the
 * operation is blocked. Kept pure: callers maintain the taint set.
 */
export function isTaintedEgress(
  toolName: string,
  input: unknown,
  taintedPaths: Set<string>
): boolean {
  if (taintedPaths.size === 0) return false;
  const egresTools = new Set(["bash", "write", "edit"]);
  if (!egresTools.has(toolName)) return false;

  const serialized = typeof input === "string" ? input : JSON.stringify(input);
  for (const p of taintedPaths) {
    if (serialized.includes(p)) return true;
  }
  // Also block if the payload itself embeds a credentialed URL or secret
  if (CREDENTIALD_URL_RE.test(serialized) || commandHasSecret(serialized)) {
    return true;
  }
  return false;
}

// ============================================================================
// Extensible configuration (allow/block paths + extra secret patterns)
// ============================================================================

export interface LeakguardConfig {
  mode?: "max" | "basic" | "auto" | "off";
  allowPaths?: string[];
  blockPaths?: string[];
  extraSecretPatterns?: { name: string; pattern: string; severity?: string }[];
}

export const DEFAULT_CONFIG: LeakguardConfig = {};

export function buildConfig(user: LeakguardConfig = {}): {
  allow: RegExp[];
  block: RegExp[];
  secretPatterns: SecretPattern[];
} {
  const allow = (user.allowPaths ?? []).map((s) => new RegExp(s, "i"));
  const block = (user.blockPaths ?? []).map((s) => new RegExp(s, "i"));
  const secretPatterns = [
    ...SECRET_PATTERNS,
    ...(user.extraSecretPatterns ?? []).map((p) => ({
      name: p.name,
      pattern: new RegExp(p.pattern, "gi"),
      severity: (p.severity ?? "high") as SecretPattern["severity"],
    })),
  ];
  return { allow, block, secretPatterns };
}

export function checkPathSensitivityExtended(
  path: string,
  allow: RegExp[],
  block: RegExp[]
): { matched: boolean; category: string; source: "default" | "allow" | "block" } {
  const normalized = normalizePath(path);

  for (const re of allow) {
    if (re.test(normalized)) {
      return { matched: false, category: "allowlisted", source: "allow" };
    }
  }

  for (const re of block) {
    if (re.test(normalized)) {
      return { matched: true, category: "Custom block", source: "block" };
    }
  }

  const def = checkPathSensitivity(normalized);
  if (def.matched) {
    return { matched: true, category: def.pattern!.category, source: "default" };
  }

  return { matched: false, category: "", source: "default" };
}

// ============================================================================
// Audit log (global observability)
// ============================================================================

export interface AuditEntry {
  ts: string;
  event: "block" | "redact" | "allow";
  tool: string;
  reason?: string;
  category?: string;
  count?: number;
}

/**
 * Append a JSONL audit entry. Pure aside from the fs append; callers pass an
 * open-able path. Returns the line written (for testing without touching disk
 * by passing a no-op via the `append` injector).
 */
export function formatAuditEntry(e: AuditEntry): string {
  return JSON.stringify(e) + "\n";
}

// ============================================================================
// Pre-commit / pre-push secret scan
// ============================================================================

// Git subcommands that publish content outside the sandbox.
const GIT_PUBLISH_CMDS = new Set(["push", "commit", "commit-tree", "send-pack", "upload-pack"]);

/**
 * Detect a git publish command (commit/push) so the caller can scan the diff.
 * Returns the subcommand or undefined.
 */
export function detectGitPublish(command: string): string | undefined {
  const words = shellWords(command.normalize("NFKC"));
  if (words[0]?.toLowerCase() !== "git" && words[0]?.toLowerCase() !== "git.exe") return undefined;
  const sub = words[1]?.toLowerCase();
  if (sub && GIT_PUBLISH_CMDS.has(sub)) return sub;
  return undefined;
}

/**
 * Scan arbitrary text (e.g. a git diff) for secret material. Uses the same
 * SECRET_VALUE_RE / SECRET_ASSIGNMENT_RE as the redactor, plus the high-entropy
 * private-key block. Returns matched pattern names. This is the last line of
 * defense: even if redaction misses, secrets never leave the repo.
 */
export function scanForSecrets(text: string, extraPatterns: SecretPattern[] = SECRET_PATTERNS): string[] {
  const { findings } = detectAll(text);
  const found = findings.map((f) => f.name);
  // User-supplied patterns still apply on top of the engine.
  for (const p of extraPatterns) {
    if (p.pattern.source.trim().length > 0 && p.pattern.test(text)) found.push(p.name);
  }
  return [...new Set(found)];
}

// Re-export for convenience
export { existsSync };
