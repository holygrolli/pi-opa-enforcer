# opa-enforcer

Pi extension that evaluates every Pi `tool_call` against Open Policy Agent (OPA) Rego and writes an audit JSONL file.

## Policy contract

Policy files use the OPA/Rego package `opa.enforcer` and must expose a boolean `allow` value. For example:

```rego
package opa.enforcer

import rego.v1

default allow := false

allow if input.tool.name != "bash"
allow if input.tool.name == "bash" and startswith(input.tool.input.command, "git ")
```

The policy input is:

```json
{
  "tool": {"name": "bash", "call_id": "...", "input": {"command": "git status"}},
  "cwd": "/project",
  "session": {"id": "...", "file": "/...jsonl"}
}
```

If policies exist but OPA is unavailable, evaluation fails closed. If no policy is found, calls are allowed. Set `OPA_ENFORCER_OPA_BIN` to the OPA executable, and optionally `OPA_ENFORCER_POLICY` to a file/directory list (separated by the platform path delimiter). Otherwise policies are recursively loaded from:

1. `$HOME/.pi/agent`
2. `<project>/.pi`
3. the current project directory

## Audit log

Each call and result is JSONL at `<default-session-file>.audit.jsonl`, next to Pi's default session log. Blocked calls are logged before the block is returned. Result records include successful and failed tool executions.

OPA must be installed separately (`opa eval` is used as the Rego interpreter). A call is allowed when any discovered policy returns `true`; otherwise evaluation fails closed. Audit-write failures also fail closed because the extension cannot guarantee compliance auditing.

## Package development and installation

This directory is a self-contained Pi package. Install dependencies and verify it with:

```bash
npm install
npm run check
npm test
npm run build
```

The package manifest points Pi at `dist/index.js`. `npm pack --dry-run` verifies the publishable contents. Install a packed or published package with `pi install npm:@pi-pa/opa-enforcer` (or use the local directory while developing). The package declares `@earendil-works/pi-coding-agent` as a peer dependency supplied by Pi.

OPA must be installed separately. Load the source extension directly from `.pi/extensions/opa-enforcer/` during local development, or install the package through Pi. Generated `dist/` and `node_modules/` are intentionally excluded from version control.
