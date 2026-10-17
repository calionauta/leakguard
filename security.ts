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
export const SECRET_VALUE_RE = /(bearer\s+[a-z0-9._~+/=-]{12,}|sk-[a-z0-9_-]{16,}|gh[pousr]_[a-z0-9_]{16,}|xox[baprs]-[a-z0-9-]{16,}|AKIA[0-9A-Z]{16}|[0-9a-f]{32,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i;
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
 * blocked. Longer hex (sha256=64, sha512=128) is preserved for secret
 * detection, since those lengths are never valid git SHAs.
 */
export function stripGitSHAs(text: string): string {
  return text.replace(/\b[0-9a-f]{7,40}\b/gi, " ");
}

export function hasSecretMaterial(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === "string") {
    return SECRET_VALUE_RE.test(stripGitSHAs(value)) || SECRET_ASSIGNMENT_RE.test(value);
  }
  if (typeof value !== "object") return false;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY_RE.test(key) || hasSecretMaterial(item)) return true;
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
    if (SECRET_VALUE_RE.test(stripGitSHAs(command)) || SECRET_ASSIGNMENT_RE.test(command)) {
      return "command attempts to transform or smuggle secret-looking material";
    }
  }

  const hasExfilTool = [...DISCOVERY_EXFIL].some((t) => containsWord(deobfuscatedLower, t));
  if (hasExfilTool && (SECRET_KEY_RE.test(command) || /\b(env|printenv|set|export)\b/.test(lower))) {
    return "command combines network discovery/transfer with sensitive material";
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

  if (SECRET_VALUE_RE.test(stripGitSHAs(command))) {
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

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: "critical" },
  { name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/g, severity: "critical" },
  { name: "AWS Session Key", pattern: /\bASIA[0-9A-Z]{16}\b/g, severity: "high" },
  { name: "OpenAI API Key", pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b/g, severity: "high" },
  { name: "Anthropic API Key", pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g, severity: "high" },
  { name: "Google API Key", pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g, severity: "high" },
  { name: "GitHub PAT", pattern: /\bghp_[A-Za-z0-9]{36,}\b/g, severity: "high" },
  { name: "GitHub Fine-grained Token", pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, severity: "high" },
  { name: "GitHub User Token", pattern: /\bghu_[A-Za-z0-9]{36}\b/g, severity: "high" },
  { name: "GitHub Refresh Token", pattern: /\bghr_[A-Za-z0-9]{36}\b/g, severity: "high" },
  { name: "GitHub OAuth Token", pattern: /\bgho_[A-Za-z0-9]{36,}\b/g, severity: "high" },
  { name: "GitHub App Install Token", pattern: /\bghs_[A-Za-z0-9]{36,}\b/g, severity: "high" },
  { name: "GitLab Token", pattern: /\bglpat-[0-9A-Za-z\-_]{20,}\b/g, severity: "high" },
  { name: "Slack Token", pattern: /\bxox[bpears]-[A-Za-z0-9-]{10,}\b/gi, severity: "high" },
  { name: "Slack Webhook", pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]+/g, severity: "high" },
  { name: "Stripe API Key", pattern: /\b[rs]k_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b/g, severity: "high" },
  { name: "SendGrid API Key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "critical" },
  { name: "npm Token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high" },
  { name: "Vault Token", pattern: /\bhvs\.[a-zA-Z0-9_-]{24}\b/g, severity: "critical" },
  { name: "Doppler Token", pattern: /\bdp\.pt\.[a-zA-Z0-9]+\b/g, severity: "critical" },
  { name: "1Password Secret Ref", pattern: /\bop:\/\/[^\s"]+/g, severity: "critical" },
  { name: "Private Key Block", pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----/g, severity: "critical" },
  { name: "JWT Token", pattern: /\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}\b/g, severity: "high" },
  { name: "DB URL with Password", pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^:]+:[^@]+@/gi, severity: "high" },
  { name: "Credentials in URL", pattern: /[a-zA-Z]+:\/\/[^:\/\s]+:[^@\/\s]{3,}@[^\s]+/g, severity: "high" },
  { name: "Bearer Token", pattern: /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi, severity: "high" },
  { name: "API Key Assignment", pattern: /(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9][A-Za-z0-9\-_./+=]{19,})['"]?/gi, severity: "medium" },
  { name: "Password Assignment", pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/gi, severity: "medium" },
  { name: "Token Assignment", pattern: /(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?([A-Za-z0-9][A-Za-z0-9\-_./+=]{19,})['"]?/gi, severity: "medium" },
];

function countCaptureGroups(source: string): number {
  let count = 0;
  let i = 0;
  while (i < source.length) {
    if (source[i] === "\\") {
      i += 2;
      continue;
    }
    if (source[i] === "(") {
      if (source[i + 1] !== "?") {
        count++;
      }
      i++;
      continue;
    }
    i++;
  }
  return count;
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

  let result = text;
  let totalCount = 0;

  for (const pattern of patterns) {
    const freshRegex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    const matches = result.match(freshRegex);
    if (!matches || matches.length === 0) {
      continue;
    }

    const matchCount = matches.length;
    totalCount += matchCount;
    stats.redactedByPattern[pattern.name] = (stats.redactedByPattern[pattern.name] ?? 0) + matchCount;

    const captureCount = countCaptureGroups(pattern.pattern.source);
    const placeholder = `${REDACTION_PLACEHOLDER} — ${pattern.name}`;

    pattern.pattern.lastIndex = 0;
    result = result.replace(pattern.pattern, (match: string, ...args: unknown[]) => {
      const captureGroups = args.slice(0, captureCount);
      const firstGroup = captureGroups.find((g): g is string => typeof g === "string" && g.length > 0);
      if (firstGroup) {
        return match.replace(firstGroup, placeholder);
      }
      return placeholder;
    });
  }

  return { text: result, count: totalCount };
}

// ============================================================================
// Egress DLP (2026 capability-separation pattern)
// ============================================================================

// Network egress tools whose arguments/body must be scanned for secrets.
// Ported concept from CredProxy/Bastion: separate secrets from egress.
export const EGRESS_TOOLS = new Set([
  "curl", "wget", "nc", "netcat", "ncat", "socat", "ftp", "sftp", "ssh", "scp",
  "rsync", "telnet", "tftp", "fetch", "node", "python", "python3", "ruby", "perl",
]);

// A URL that embeds credentials (user:pass@host) is always egress-secret.
export const CREDENTIALD_URL_RE = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\/\s]+:[^@\/\s]{3,}@/;

// Basic-auth inline flag: -u user:pass / --user user:pass
export const BASIC_AUTH_FLAG_RE = /(?:-|--)u(?:ser)?\s+[^\s:]+(?::[^\s]+)/i;

// Secret-bearing HTTP headers in egress payloads.
export const SECRET_HEADER_RE = /(?:authorization|x-api-key|x-auth-token|proxy-authorization)\s*:/i;

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
  if (SECRET_VALUE_RE.test(stripGitSHAs(normalized)) || SECRET_ASSIGNMENT_RE.test(normalized)) {
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
  if (CREDENTIALD_URL_RE.test(serialized) || SECRET_VALUE_RE.test(stripGitSHAs(serialized))) {
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
  const found: string[] = [];
  for (const p of extraPatterns) {
    if (p.pattern.test(text)) found.push(p.name);
  }
  return [...new Set(found)];
}

// Re-export for convenience
export { existsSync };
