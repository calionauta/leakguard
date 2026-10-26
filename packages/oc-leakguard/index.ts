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
 *
 * TWO ENTRY POINTS, ON PURPOSE
 *
 * OpenCode 2.x replaced the V1 plugin shape with V2, and the shapes are not
 * compatible. A V1 module exports `{ id, server }`; the V2 loader rejects that
 * with "Plugin must export a default definition with an id and an effect or setup
 * function" and — critically — only WARNS. The plugin silently never ran.
 *
 * That failure is invisible from the inside: no error reaches the model, no hook
 * is missing from the plugin's own perspective, and every unit test passes
 * because the hooks really do work when invoked directly. It was found by reading
 * ~/.local/share/opencode/log/opencode.log, not by testing the plugin.
 *
 * So both are exported: `server` for 1.x, `setup` for 2.x. Whichever the running
 * harness understands is used; the other is ignored.
 */

import {
  detectWithEngine,
  engineStatusLine,
  redactText,
  resolveEngine,
  scanAndRedact,
  ENGINE_BIN,
  updaterHint,
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
  console.warn(`leakguard: install the engine with ${updaterHint()}`);
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

/**
 * V2 adapter.
 *
 * V2 does not pass hooks as a plain object; it hands you a context and expects
 * you to register each hook through it. The semantics we rely on are unchanged,
 * so this only rewires: same verdicts, same messages, same redaction.
 *
 * The context shape is structural, not imported, because it is not published as a
 * type and the plugin must load on both majors without a version check.
 */
type V2Args = Record<string, unknown>;

interface V2Context {
  location?: { directory?: string };
  tool?: {
    hook?: (
      name: string,
      handler: (call: unknown) => Promise<void>,
    ) => Promise<unknown>;
  };
  session?: {
    hook?: (
      name: string,
      handler: (request: any) => Promise<void>,
    ) => Promise<unknown>;
  };
  event?: { subscribe?: (options?: { signal?: AbortSignal }) => AsyncIterable<any> };
}

export const setupLeakguardV2 = async (ctx: V2Context): Promise<() => Promise<void>> => {
  const status = engineStatusLine();
  offerInstall(status);

  const toolHook = ctx.tool?.hook;
  const sessionHook = ctx.session?.hook;

  if (typeof toolHook === "function") {
    // Before: same two checks, reading the call's declared arguments.
    await toolHook("execute.before", async (raw) => {
      const call = raw as { tool?: string; id?: string; sessionID?: string; input?: V2Args };
      const args = (call.input ?? {}) as V2Args;
      const tool = String(call.tool ?? "");

      if (PATH_TOOLS.has(tool)) {
        const target = String(args.filePath ?? args.path ?? args.file ?? "");
        const reason = blockedPathReason(target);
        if (reason) throw new Error(pathGuardMessage(tool, reason, target));
      }

      if (tool === "bash") {
        const verdict = checkEgress(String(args.command ?? ""));
        if (verdict.error || verdict.blocked) throw new Error(egressMessage(verdict));
      }
    });

    // After: redact in place. V2 carries the result on the call object, so the
    // text is rewritten there rather than in a separate output record.
    await toolHook("execute.after", async (raw) => {
      const call = raw as { tool?: string; result?: any; status?: string };
      if (call.status !== "completed") return;
      const result = call.result;
      if (!result || typeof result !== "object") return;

      const rewrite = (text: string): string => {
        if (!text) return text;
        const scan = detectWithEngine(text);
        if (scan.findings.length === 0) return text;
        const r = redactText(text, scan.findings);
        return r.count > 0 ? r.text : text;
      };

      if (typeof (result as { content?: unknown }).content === "string") {
        const before = (result as { content: string }).content;
        const after = rewrite(before);
        if (after !== before) (result as { content: string }).content = after;
        return;
      }

      const content = (result as { content?: unknown }).content;
      if (Array.isArray(content)) {
        for (const part of content) {
          if (part && part.type === "text" && typeof part.text === "string") {
            part.text = rewrite(part.text);
          }
        }
      }
    });
  }

  // The engine state has to reach the MODEL, not just the console.
  if (typeof sessionHook === "function") {
    await sessionHook("context", async (request: any) => {
      if (!status) return;
      const system = request?.system;
      if (!Array.isArray(system)) return;
      const last = system[system.length - 1];
      if (last && typeof last.text === "string") {
        system[system.length - 1] = { ...last, text: `${last.text}\n\n${status}` };
      } else {
        system.push({ type: "text", text: status });
      }
    });
  }

  return async () => {
    /* nothing to tear down: hook registrations end with the session */
  };
};

/**
 * One default that both majors accept. V2 validates `effect` or `setup`; V1 reads
 * `server`. Extra keys are ignored by both.
 */
export default {
  id: "leakguard",
  server: Leakguard,
  setup: setupLeakguardV2,
};
