import { afterEach, describe, expect, it } from "vitest";
import { appendAudit, auditPath, evaluate, findRego, policyFiles } from "../index.js";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const input = {
  tool: { name: "bash", call_id: "call-1", input: { command: "git status" } },
  cwd: "/tmp/project",
  session: { id: "session-1", file: "/tmp/project/session.jsonl" },
};

describe("opa-enforcer helpers", () => {
  const originalPolicy = process.env.OPA_ENFORCER_POLICY;
  const originalOpa = process.env.OPA_ENFORCER_OPA_BIN;

  afterEach(() => {
    if (originalPolicy === undefined) delete process.env.OPA_ENFORCER_POLICY;
    else process.env.OPA_ENFORCER_POLICY = originalPolicy;
    if (originalOpa === undefined) delete process.env.OPA_ENFORCER_OPA_BIN;
    else process.env.OPA_ENFORCER_OPA_BIN = originalOpa;
  });

  it("allows calls when no policy exists", async () => {
    expect(await evaluate(input, [])).toEqual({ allow: true, reason: "No opa.enforcer policy found" });
  });

  it("fails closed when OPA is unavailable", async () => {
    process.env.OPA_ENFORCER_OPA_BIN = path.join(os.tmpdir(), "missing-opa-binary");
    const result = await evaluate(input, ["/tmp/policy.rego"]);
    expect(result.allow).toBe(false);
    expect(result.reason).toContain("Rego interpreter unavailable");
  });

  it("finds Rego files recursively while skipping dependencies", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "opa-enforcer-"));
    await fs.mkdir(path.join(root, "nested", "node_modules"), { recursive: true });
    await fs.writeFile(path.join(root, "policy.rego"), "package opa.enforcer");
    await fs.writeFile(path.join(root, "nested", "other.rego"), "package opa.enforcer");
    await fs.writeFile(path.join(root, "nested", "node_modules", "ignored.rego"), "package opa.enforcer");
    await expect(findRego(root)).resolves.toEqual([
      path.join(root, "nested", "other.rego"),
      path.join(root, "policy.rego"),
    ]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("accepts explicitly configured Rego files", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "opa-enforcer-"));
    const file = path.join(root, "policy.rego");
    await fs.writeFile(file, "package opa.enforcer");
    process.env.OPA_ENFORCER_POLICY = file;
    await expect(policyFiles(path.join(root, "project"))).resolves.toContain(file);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("writes one JSONL audit record", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "opa-enforcer-"));
    const file = path.join(root, "audit.jsonl");
    await appendAudit(file, { timestamp: new Date().toISOString(), event: "tool_call", tool: input.tool, cwd: input.cwd });
    const lines = (await fs.readFile(file, "utf8")).trim().split("\n");
    expect(JSON.parse(lines[0])).toMatchObject({ event: "tool_call", cwd: input.cwd });
    await fs.rm(root, { recursive: true, force: true });
  });

  it("derives audit files next to sessions", () => {
    expect(auditPath("/tmp/session.jsonl")).toBe("/tmp/session.jsonl.audit.jsonl");
  });
});
