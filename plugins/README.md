# Other harnesses

`pi-leakguard` itself is a **pi** extension: it registers `tool_call` and
`tool_result` hooks through the pi ExtensionAPI, which is what gives it the
confirm prompts, the audit log, and `/leakguard` commands.

These plugins carry the same thin layer — path guard, egress check, redaction —
to other harnesses. They delegate detection to the **same** betterleaks binary
and config, so the rule set is identical everywhere and there is still only one
thing to update.

| file | harness | install |
|---|---|---|
| `opencode.ts` | [OpenCode](https://opencode.ai) | copy to `~/.config/opencode/plugins/leakguard.ts` |

## What is and is not shared

Shared, because it is the engine's job:
- 471 detection rules, 218 with provider-side validation
- version pinning (`~/.config/betterleaks/VERSION`) and drift reporting

Not shared, because it is per-harness by nature:
- the hook API (`tool_call`/`tool_result` vs `tool.execute.before`/`.after`)
- confirm prompts and `/leakguard` commands (pi extension only)
- the audit log (pi extension only)

Each plugin keeps its own path guard and egress rule rather than importing them
from the extension, because pi's TypeScript extension API and OpenCode's plugin
API do not share a module format. That duplication is ~40 lines of path
patterns, not a copy of the detection rules — the part that actually drifts is
delegated in both.
