/**
 * core/egress.ts — "is this command sending a credential somewhere?"
 *
 * This is the layer the engine genuinely cannot replace. betterleaks judges
 * CONTENT: is there a credential in this text? It has a `curl-auth-header` rule
 * that needs a curl invocation to establish egress context. A script sending the
 * same header via `requests`, `http`, `xh`, or a bare assignment is invisible to
 * it, and those are the shapes people actually write.
 *
 * So: the engine answers "is there a credential", this module answers "is it
 * leaving", and a block requires BOTH. Sending alone is ordinary. A credential
 * alone is ordinary (reading a token is not a leak). The pair is the leak.
 *
 * Traps encoded here, each of which produced a real false positive in this
 * project while shipping 0.9.x:
 *
 *   - tool names matched as words: "ssh" and "curl" inside a CHANGELOG, a commit
 *     message or a heredoc are prose, not invocations
 *   - `export` treated as exfiltration on its own: `export PATH=...` has no
 *     credential in it
 *   - the header NAME `Authorization:` treated as a secret: documentation about
 *     an HTTP header was blocked, and the value was never examined
 */

import { detectWithEngine, ENGINE_BIN, ENGINE_CFG } from "./engine-client.js";

/** Commands that move data off the machine. */
export const EGRESS_TOOLS = new Set([
  "curl",
  "http",
  "https",
  "httpie",
  "xh",
  "wget",
  "nc",
  "ncat",
  "netcat",
  "socat",
  "telnet",
  "scp",
  "rsync",
  "ftp",
  "lftp",
  "ssh",
  "nmap",
  "dig",
  "host",
  "nslookup",
]);

/**
 * A real network INVOCATION: the tool name in command position — at the start of
 * the string, after a shell separator, or after sudo/doas. Word-boundary matching
 * on the tool name alone fires on prose, which is how a `git commit -m` message
 * containing the word "ssh" got blocked.
 */
export const EXFIL_INVOCATION_RE = new RegExp(
  "(?:^|[;&|(`]|\\$\\()\\s*(?:sudo|doas|command|exec|env)\\s+(?:-[A-Za-z]+\\s+)*" +
    "|(?:^|[;&|(`]|\\$\\()\\s*(?:" +
    [...EGRESS_TOOLS].sort((a, b) => b.length - a.length).join("|") +
    ")\\b",
  "i",
);

/**
 * A path naming a credential store is sensitive material on its own:
 * `nc host < ~/.env` leaks whatever is in that file.
 */
export const SENSITIVE_PATH_RE =
  /(?:\.(?:env|aws|ssh|gnupg|kube|docker|npmrc|pypirc|netrc|git-credentials|secrets)(?=[\s/'"`)]|$)|\.env\b)/i;

/** An environment dump, which carries whatever is exported. */
export const ENV_DUMP_RE = /\b(?:printenv|env\s*\||env\s*$|cat\s+\/proc\/self\/environ)/im;

/**
 * A secret-bearing HTTP header carrying a VALUE.
 *
 * Deliberately requires the value. The bare name `Authorization:` appears in
 * changelogs, docs, code comments and error messages; flagging the name alone
 * blocked documenting the feature being shipped.
 *
 * Tolerates a closing quote between the name and the colon, because the most
 * common programmatic form is `headers={"Authorization": "Bearer ..."}` — the
 * shape that was invisible before this was fixed.
 */
const HEADER_VALUE = "(?!<)[A-Za-z0-9._~+\\/-]";
export const SECRET_HEADER_RE = new RegExp(
  "(?:authorization|x-api-key|x-auth-token|proxy-authorization)[\"'\\u201c]?\\s*:\\s*(?:" +
    "(?:bearer|basic|token|digest)\\s+" + HEADER_VALUE + "{4,}" +
    "|" + HEADER_VALUE + "{8,}" +
    ")",
  "i",
);

export interface EgressVerdict {
  blocked: boolean;
  reason?: string;
  /** Rule names, so the message can say WHAT was found, never the value. */
  found?: string[];
  /** Set when detection could not run: the caller must fail closed. */
  error?: string;
}

/**
 * Judge a shell command.
 *
 * A command is blocked only when it is a real egress invocation AND carries a
 * credential (engine finding, a credential path, or an env dump). The engine is
 * asked once; when it is unavailable the caller gets `error` and must refuse.
 */
export function checkEgress(
  command: string,
  opts?: { bin?: string; cfg?: string },
): EgressVerdict {
  if (!command) return { blocked: false };

  const normalized = command.normalize("NFKC");
  // Shell-quoting and backslash escapes are the cheapest way to slip a value past
  // a text matcher, so judge the deobfuscated form too.
  const deobfuscated = normalized.replace(/\\(.)/g, "$1").replace(/['"`]/g, "");

  const isInvocation = EXFIL_INVOCATION_RE.test(deobfuscated);
  const hasHeaderValue = SECRET_HEADER_RE.test(normalized);
  const hasSensitivePath = SENSITIVE_PATH_RE.test(normalized);
  const hasEnvDump = ENV_DUMP_RE.test(normalized);

  // Nothing is leaving, or nothing recognisably sensitive is present.
  if (!isInvocation && !hasHeaderValue) return { blocked: false };
  if (!isInvocation && hasHeaderValue) {
    // A header with a value and no invocation is a credential in a script, not a
    // transfer. Report it as detected content, not as egress.
    return { blocked: false };
  }

  if (hasSensitivePath) {
    return { blocked: true, reason: "egress of a sensitive file", found: ["sensitive path"] };
  }

  const scan = detectWithEngine(normalized, opts);
  if (scan.error) {
    return { blocked: false, error: scan.error };
  }
  if (scan.findings.length > 0) {
    return {
      blocked: true,
      reason: "egress command carries a credential",
      found: [...new Set(scan.findings.map((f) => f.name))],
    };
  }

  if (hasEnvDump) {
    return { blocked: true, reason: "egress combined with an environment dump", found: ["env dump"] };
  }
  if (hasHeaderValue) {
    return {
      blocked: true,
      reason: "egress command sends a credential in an HTTP header",
      found: ["secret header"],
    };
  }

  return { blocked: false };
}

/** Message for a blocked command, phrased so a retrying model changes approach. */
export function egressMessage(v: EgressVerdict): string {
  const what = v.found?.length ? ` (${v.found.join(", ")})` : "";

  if (v.error) {
    return [
      `leakguard refused this command: secret detection is unavailable (${v.error}).`,
      "",
      "This is not a false positive and not about your command: the scanner that",
      "decides whether the payload carries a credential could not run, so the gate",
      "fails closed instead of waving everything through.",
      "",
      "What to do:",
      "  1. Run the command without the network part, if the two can be separated.",
      "  2. Install the engine (the human runs `~/.bin/betterleaks-update`, or",
      "     `~/bin/betterleaks-update` on Linux) and try again.",
      "  3. If neither is possible, ask the human to run it themselves.",
    ].join("\n");
  }

  return [
    `leakguard blocked this command: ${v.reason}${what}.`,
    "",
    "The VALUE tripped this, not the spelling — renaming a variable, re-quoting, or",
    "splitting the command will produce the same block. This rule fires when a",
    "command both leaves the machine AND carries a credential.",
    "",
    "What to do, cheapest first:",
    "  1. Drop the credential from the command. Almost every diagnostic works",
    "     without it (a HEAD request, a status endpoint, `--dry-run`).",
    "  2. If the target is local (`localhost`, a unix socket), that is allowed —",
    "     the rule is about sending secrets OFF the machine.",
    "  3. Need the real call? Ask the human to run it, so the secret never enters",
    "     this transcript.",
  ].join("\n");
}

export { ENGINE_BIN, ENGINE_CFG };
