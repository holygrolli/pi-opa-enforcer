import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { CONFIG_DIR_NAME } from "@earendil-works/pi-coding-agent";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";

/**
 * OPA policy input. Policies must use `package opa.enforcer` and expose `allow`.
 * Example: `allow if input.tool.name == "read"`.
 */
export type OpaEnforcerInput = {
  tool: { name: string; call_id: string; input: unknown };
  cwd: string;
  session: { id?: string; file?: string };
};

type OpaResponse = { result?: Array<{ expressions?: Array<{ value?: unknown }> }> };
type AuditRecord = {
  timestamp: string;
  event: "tool_call" | "tool_result";
  allowed?: boolean;
  blocked?: boolean;
  reason?: string;
  tool: { name: string; call_id: string; input: unknown };
  cwd: string;
  session_file?: string;
  policy_files?: string[];
};

const POLICY_ENV = "OPA_ENFORCER_POLICY";
const OPA_ENV = "OPA_ENFORCER_OPA_BIN";

export async function exists(file: string): Promise<boolean> {
  try { await fs.access(file); return true; } catch { return false; }
}

export async function findRego(root: string): Promise<string[]> {
  const output: string[] = [];
  if (!(await exists(root))) return output;
  const walk = async (dir: string): Promise<void> => {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile() && entry.name.endsWith(".rego")) output.push(full);
    }
  };
  await walk(root);
  return output;
}

export async function policyFiles(cwd: string): Promise<string[]> {
  const home = process.env.HOME ?? os.homedir();
  const configured = process.env[POLICY_ENV]?.split(path.delimiter).filter(Boolean) ?? [];
  const roots = [
    ...configured,
    path.join(home, ".pi", "agent"),
    path.join(cwd, CONFIG_DIR_NAME),
    cwd,
  ];
  const found = new Set<string>();
  for (const root of roots) {
    const stat = await fs.stat(root).catch(() => undefined);
    if (!stat) continue;
    if (stat.isFile() && root.endsWith(".rego")) found.add(path.resolve(root));
    else if (stat.isDirectory()) for (const file of await findRego(root)) found.add(path.resolve(file));
  }
  return [...found].sort();
}

function run(command: string, args: string[], input: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input);
  });
}

export async function evaluate(input: OpaEnforcerInput, files: string[]): Promise<{ allow: boolean; reason?: string }> {
  if (files.length === 0) return { allow: true, reason: "No opa.enforcer policy found" };
  const opa = process.env[OPA_ENV] || "opa";
  const errors: string[] = [];

  for (const file of files) {
    const args = ["eval", "--format=json", "--stdin-input", "--data", file, "data.opa.enforcer.allow"];
    let result;
    try { result = await run(opa, args, JSON.stringify(input)); }
    catch (error) { return { allow: false, reason: `Rego interpreter unavailable: ${String(error)}` }; }

    if (result.code !== 0) {
      errors.push(`${file}: ${result.stderr.trim() || `exit ${result.code}`}`);
      continue;
    }

    try {
      const parsed = JSON.parse(result.stdout) as OpaResponse;
      const value = parsed.result?.[0]?.expressions?.[0]?.value;
      if (value === true) return { allow: true };
      if (value !== false) errors.push(`${file}: Policy did not return boolean data.opa.enforcer.allow`);
    } catch (error) {
      errors.push(`${file}: Invalid Rego interpreter response: ${String(error)}`);
    }
  }

  if (errors.length > 0) return { allow: false, reason: `Rego evaluation failed: ${errors.join("; ")}` };
  return { allow: false, reason: "Tool denied by Open Policy Agent policy. Do not try again!" };
}

export function auditPath(sessionFile: string | undefined): string {
  if (sessionFile) return `${sessionFile}.audit.jsonl`;
  const dir = path.join(process.env.HOME ?? os.homedir(), ".pi", "agent", "sessions");
  return path.join(dir, `opa-enforcer-${process.pid}.audit.jsonl`);
}

export async function appendAudit(file: string, record: AuditRecord): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.appendFile(file, JSON.stringify(record) + "\n", "utf8");
}

export default function (pi: ExtensionAPI) {
  let cwd = process.cwd();
  let sessionFile: string | undefined;
  let files: string[] = [];
  const calls = new Map<string, OpaEnforcerInput>();

  pi.on("session_start", async (_event, ctx) => {
    cwd = ctx.cwd;
    sessionFile = ctx.sessionManager.getSessionFile() ?? undefined;
    files = await policyFiles(cwd);
  });

  pi.on("tool_call", async (event, ctx) => {
    // Refresh on every call so policy edits take effect without /reload.
    files = await policyFiles(ctx.cwd);
    const input: OpaEnforcerInput = {
      tool: { name: event.toolName, call_id: event.toolCallId, input: event.input },
      cwd: ctx.cwd,
      session: { id: ctx.sessionManager.getSessionId(), file: ctx.sessionManager.getSessionFile() ?? undefined },
    };
    calls.set(event.toolCallId, input);
    const decision = await evaluate(input, files);
    const record: AuditRecord = {
      timestamp: new Date().toISOString(), event: "tool_call", allowed: decision.allow,
      blocked: !decision.allow, reason: decision.reason, tool: input.tool, cwd: ctx.cwd,
      session_file: input.session.file, policy_files: files,
    };
    try {
      await appendAudit(auditPath(input.session.file), record);
    } catch (error) {
      return { block: true, reason: `Audit log unavailable: ${String(error)}` };
    }
    if (!decision.allow) return { block: true, reason: decision.reason ?? "Tool denied by Open Policy Agent policy. Do not try again!" };
    return undefined;
  });

  pi.on("tool_execution_end", async (event, ctx) => {
    const file = ctx.sessionManager.getSessionFile() ?? sessionFile;
    const input = calls.get(event.toolCallId);
    calls.delete(event.toolCallId);
    await appendAudit(auditPath(file), {
      timestamp: new Date().toISOString(), event: "tool_result",
      tool: input?.tool ?? { name: event.toolName, call_id: event.toolCallId, input: undefined },
      cwd: ctx.cwd, session_file: file, policy_files: files,
      reason: event.isError ? "Tool returned an error" : undefined,
    });
  });
}
