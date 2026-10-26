/**
 * oc-leakguard — the OpenCode host layer.
 *
 * Detection, path rules and the egress judgement live in core/, one copy shared
 * with the pi host. This file contains ONLY what is specific to OpenCode: the
 * hook API, and turning a verdict into something the harness acts on.
 *
 * A sync script copies ../../core/ into this package's core/ so the published /
 * installed image is self-contained while the repo keeps a single source.
 *
 * Why this shape: the previous version reimplemented `resolveEngine`,
 * `detectSecrets`, `redactOutput` and `engineStatusLine` inside this file, in
 * parallel with the pi extension. The egress blind spot — a secret header sent as
 * `headers={"Authorization": "..."}` — was invisible to BOTH at once because both
 * carried the same narrow assumption, and it had to be fixed twice. Two copies of
 * an adapter is how that happens; one copy is how it stops.
 *
 * Install (git, no npm publish needed):
 *   opencode plugin add github:calionauta/leakguard
 * or copy this directory into ~/.config/opencode/plugins/leakguard/.
 */

import {
  detectWithEngine,
  engineStatusLine,
  redactText,
  resolveEngine,
  scanAndRedact,
  ENGINE_BIN,
} from "./core/engine-client.js";
import { blockedPathReason, pathGuardMessage, PATH_TOOLS } from "./core/path-guard.js";
import { checkEgress, egressMessage } from "./core/egress.js";

/**
 * Offer to install a missing engine, with consent — once per process, and never
 * without a terminal. A plugin that blocks on a prompt nobody can see is worse
 * than one that degrades loudly.
 *
 * Asymmetry is deliberate: consent to INSTALL (a new capability, once),
 * notification to UPDATE (the rule set is the thing being trusted, so a version
 * bump is a rules change and must be reviewed).
 */
let offered = false;
function offerInstall(status: string): void {
  if (!ENGINE_BIN) {
    console.warn(`leakguard: ${status}`);
  } else if (status) {
    console.warn(`leakguard: ${status}`);
  }
  if (offered || ENGINE_BIN) return;
  offered = true;
  const interactive = Boolean(process.stdin.isTTY && process.stderr.isTTY) && !process.env.CI;
  if (!interactive) return;
  console.warn("leakguard: install the engine with ~/.bin/betterleaks-update");
}

export function detectSecrets(text: string) {
  const scan = detectWithEngine(text);
  return {
    count: scan.findings.length,
    names: scan.findings.map((f) => f.ruleId),
    error: scan.error,
  };
}

export function redactOutput(text: string) {
  return scanAndRedact(text);
}

export const Leakguard = async () => {
  const status = engineStatusLine();
  offerInstall(status);

  return {
    /** Before a tool runs: path guard, then egress carrying a credential. */
    "tool.execute.before": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { args: any },
    ) => {
      const args = output.args ?? {};

      // 1. Reading or writing a protected path.
      if (PATH_TOOLS.has(input.tool)) {
        const target = String(args.filePath ?? args.path ?? args.file ?? "");
        const reason = blockedPathReason(target);
        if (reason) throw new Error(pathGuardMessage(input.tool, reason, target));
      }

      // 2. A shell command that BOTH leaves the machine AND carries a credential.
      if (input.tool === "bash") {
        const cmd = String(args.command ?? "");
        const verdict = checkEgress(cmd);
        if (verdict.error) throw new Error(egressMessage(verdict));
        if (verdict.blocked) throw new Error(egressMessage(verdict));
      }
    },

    /** After a tool returns: redact before the model ever sees the output. */
    "tool.execute.after": async (
      input: { tool: string; sessionID: string; callID: string; args: any },
      output: { title: string; output: string; metadata: any },
    ) => {
      if (typeof output.output !== "string" || output.output.length === 0) return;
      const scan = detectWithEngine(output.output);
      if (scan.findings.length === 0) return;
      const r = redactText(output.output, scan.findings);
      if (r.count > 0) {
        output.output = r.text;
        output.title = `${output.title ?? input.tool} (${r.count} secret${r.count === 1 ? "" : "s"} redacted)`;
      }
    },

    /**
     * The engine state must reach the MODEL, not only the console: an agent
     * deciding what to run next does not read a warning banner, so it can spend a
     * turn believing a gate is armed when it is not.
     */
    "experimental.chat.system.transform": async (
      _input: {},
      output: { system?: string[] },
    ) => {
      if (status && Array.isArray(output.system)) output.system.push(status);
    },

    event: async ({ event }: { event: { type: string } }) => {
      if (event?.type === "session.created" && status) console.warn(`leakguard: ${status}`);
    },
  };
};

export default { id: "leakguard", server: Leakguard };
