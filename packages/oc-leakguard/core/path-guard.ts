/**
 * core/path-guard.ts — "may the agent read this file?"
 *
 * No scanner answers this. betterleaks asks "is there a credential in this text?"
 * and has no concept of a path being off-limits, so this rule set has to exist
 * somewhere. It lives here, once, so both hosts agree.
 *
 * What must NOT live here: any re-implementation of an engine rule. That copy
 * drifts, which is why the 31 hand-written regexes were deleted from the pi
 * extension. If a credential shape is being missed, the fix belongs in
 * betterleaks.toml, not in this file.
 */

export interface BlockedPathRule {
  name: string;
  test: RegExp;
}

/**
 * Paths that are never the agent's business.
 *
 * Ordered most-specific first so the reported reason is the useful one: an SSH
 * private key should say "SSH private key", not "SSH config/keys".
 */
export const BLOCKED_PATHS: BlockedPathRule[] = [
  { name: "SSH private key", test: /(^|\/)\.ssh\/(id_|.*_rsa|.*_ed25519|.*_ecdsa|.*_dsa)/ },
  { name: "SSH keys or config", test: /(^|\/)\.ssh\// },
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
  { name: "secrets directory", test: /(^|\/)\.secrets\// },
  { name: "pi secrets directory", test: /(^|\/)\.pi-secrets\// },
  { name: "system shadow/passwd", test: /^\/etc\/(shadow|sudoers|passwd)$/ },
  { name: "macOS keychain", test: /Library\/Keychains\// },
];

/**
 * Documentation and fixtures exist to show what a credential looks like, and
 * refusing to read them makes the guard unusable for its main legitimate
 * purpose: writing and reviewing docs about secrets.
 */
export function isDocumentationPath(p: string): boolean {
  return (
    /(^|\/)(docs?|examples?|fixtures?|testdata)\//.test(p) ||
    /\.(md|mdx|rst|adoc)$/.test(p) ||
    /\.(example|sample|template)(\.[^.]+)?$/.test(p)
  );
}

/** The rule that rejects this path, or undefined when the path is allowed. */
export function blockedPathReason(target: string): string | undefined {
  if (!target) return undefined;
  if (isDocumentationPath(target)) return undefined;
  for (const rule of BLOCKED_PATHS) {
    if (rule.test.test(target)) return rule.name;
  }
  return undefined;
}

/**
 * The message both hosts show when a path is refused.
 *
 * Structure is deliberate and matches llm-hints.ts: what was blocked, where, and
 * what to do about it. The earlier one-sentence version ("Read it by key name")
 * told the model a remedy but not what had matched, so the only move it could see
 * was retrying with a different spelling — which the message then had to forbid in
 * the same breath, without saying why.
 *
 * Kept here rather than in the pi host because the OpenCode host has no
 * llm-hints.ts and would otherwise keep the weaker wording.
 */
export function pathGuardMessage(tool: string, reason: string, target: string): string {
  return [
    `leakguard blocked this ${tool}: ${reason}.`,
    `  ${target}`,
    "",
    "Nothing was read, so no credential was exposed.",
    "What to do, cheapest first:",
    "  1. You probably do not need the contents. Reference the file by path if you",
    "     only need to prove it exists, or ask the human whether it is set.",
    "  2. Need one non-secret value from it? Ask the human for that value.",
    "  3. Genuinely need the file? Ask the human to run `/leakguard allow-once`.",
    "",
    "Do not retry with different spelling, a relative path, or a symlink: the check",
    "resolves the real path, so the outcome will be identical.",
  ].join("\n");
}

/** Tools whose arguments name a file the agent intends to read or write. */
export const PATH_TOOLS = new Set(["read", "write", "edit", "patch", "view"]);
