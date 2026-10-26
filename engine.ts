/**
 * Detection engine: betterleaks — pi host binding.
 *
 * This file is a THIN BINDING, not an implementation. All detection logic lives
 * in `core/engine-client.ts`, which both hosts (pi and OpenCode) consume; this
 * module only re-exports it under the names the pi layer already imports and
 * adds `applyRedaction` as the historical alias for `redactText`.
 *
 * WHY THE INDIRECTION EXISTS
 *
 * pi resolves a git package from the REPOSITORY ROOT (it reads the root
 * package.json and identifies git packages by repo URL, with no subdirectory
 * support), so the extension's entry point must live at the root. OpenCode
 * installs an npm-shaped package that must be self-contained, hence a synced
 * copy under packages/oc-leakguard/core/. Keeping one implementation and two
 * bindings is the only arrangement where "one engine client, two hosts" is
 * literally true rather than aspirational.
 *
 * WHAT THIS MODULE WAS
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
 *   NOT covered (retained as residuals in the shared client):
 *     - a bare `Authorization: Bearer <opaque>` line, with no curl/HTTP context
 *     - 1Password `op://` references, which are pointers, not credentials
 *
 * The 31-regex list was deleted rather than kept as a fallback. A copy of rules
 * the engine already owns buys no coverage, and a copy that silently drifts is
 * worse than no copy.
 *
 * WHAT THE SHARED CLIENT DOES NOT DO
 *
 * Detection only. Every judgement layer in leakguard — path guards, symlink
 * resolution, obfuscation, taint tracking, egress DLP, confirm prompts — stays
 * in place, because betterleaks answers "is there a credential in this text?"
 * and nothing else. It has no concept of "may the agent read this file".
 */

export {
  ENGINE_BIN,
  ENGINE_CFG,
  ENGINE_VERSION_FILE,
  REDACTION_PLACEHOLDER,
  RESIDUAL_PATTERNS,
  type EngineFinding,
  type EngineStatus,
  type ScanResult,
  ruleName,
  updaterHint,
  detectWithEngine,
  detectAll,
  redactText,
  scanAndRedact,
  engineStatus,
  engineStatusLine,
  recordEngineVersion,
} from "./core/engine-client.js";

/** Historical name for `redactText`, kept because callers import it. */
export { redactText as applyRedaction } from "./core/engine-client.js";
