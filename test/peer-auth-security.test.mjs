import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { buildPeerEnvelope, capabilityAllows, signPeerEnvelope, validatePeerEnvelope, verifyPeerEnvelopeSignature } from "../src/peer-auth-canonical.mjs";
import { PeerAuthKeyStore } from "../src/peer-auth-keystore-win32.mjs";
import { PeerAuthStore } from "../src/peer-auth-store.mjs";
import { inspectCodexTask, provisionPeerAuth } from "../src/peer-auth-setup.mjs";
import { readClaudePromptContext } from "../src/peer-protocol.mjs";

const roots = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
function root() { const value = fs.mkdtempSync(path.join(os.tmpdir(), "peer-auth-security-")); roots.push(value); return fs.realpathSync.native(value); }

function envelope(cwd) {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const key = publicKey.export({ type: "spki", format: "der" });
  return buildPeerEnvelope({ issuedAt: 1, expiresAt: 1001, sender: { agent: "claude", account_fingerprint: "a", task_id: "c", session_id: "s", turn_id: "t" }, recipient: { agent: "codex", account_fingerprint: "b", task_id: "d", session_id: null }, scope: { canonical_cwd: cwd, cwd_identity: "1:2", project_id: "p", project_host_id: "local" }, originatingUserTaskId: "c", allowedRoots: [cwd], text: "review", signerKeyId: crypto.createHash("sha256").update(key).digest("hex") });
}

describe("peer authentication canonical and storage hardening", () => {
  it("rejects noncanonical Unicode, base64url aliases, and inherited capability names", () => {
    const cwd = root(); const value = envelope(cwd);
    assert.throws(() => validatePeerEnvelope({ ...value, payload: { ...value.payload, text: "\ud800" } }), /surrogate|canonical/i);
    assert.throws(() => validatePeerEnvelope({ ...value, nonce: `${value.nonce.slice(0, -1)}B` }), /nonce/i);
    const pair = crypto.generateKeyPairSync("ed25519"); const signature = signPeerEnvelope({ ...value, signer_key_id: crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex") }, pair.privateKey);
    assert.equal(verifyPeerEnvelopeSignature({ ...value, signer_key_id: crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex") }, `${signature.slice(0, -1)}B`, pair.publicKey), false);
    assert.equal(capabilityAllows("toString", "read_only"), false);
  });

  it("validates an existing SQLite artifact before opening or repairing it", () => {
    const cwd = root(); fs.writeFileSync(path.join(cwd, "state.sqlite3"), "not sqlite");
    let protectedExisting = false;
    assert.throws(() => new PeerAuthStore({ root: cwd, validateStorage: (paths) => { if (paths.some((candidate) => candidate.endsWith("state.sqlite3"))) throw new Error("ACL drift"); }, protectStorage: () => { protectedExisting = true; } }), /ACL drift/);
    assert.equal(protectedExisting, false);
  });

  it("keeps one immutable peer parent context even after expiry", () => {
    const cwd = root(); const store = new PeerAuthStore({ root: cwd });
    const identity = { agent: "codex", task_id: "task", session_id: "", turn_id: "turn" };
    const first = envelope(cwd); const second = { ...envelope(cwd), message_id: crypto.randomUUID() };
    for (const value of [first, second]) store.issue({ envelope: value, envelopeJson: JSON.stringify(value), envelopeSha256: "0".repeat(64), signature: "signature", recipientKeyId: "recipient", direction: "claude_to_codex" });
    store.setTurnContext(identity, first.message_id, "read_only", 1);
    assert.throws(() => store.setTurnContext(identity, second.message_id, "review_only", 2), (error) => error.code === "INVALID_PARENT");
    assert.equal(store.contextsFor(identity)[0].message_id, first.message_id); store.close();
  });
});

describe("peer authentication native setup preflight", () => {
  it("rejects a preexisting junction before changing any ACL or writing a key", (t) => {
    const base = root(); const target = path.join(base, "target"); const junction = path.join(base, "auth");
    fs.mkdirSync(target);
    try { fs.symlinkSync(target, junction, "junction"); } catch (error) { t.skip(`junction unavailable: ${error.code ?? error.message}`); return; }
    let aclMutations = 0;
    const keys = new PeerAuthKeyStore({ root: junction, platform: "win32", protectAcl: () => { aclMutations += 1; }, validateAcl: () => {} });
    assert.throws(() => keys.setup(), /reparse point/);
    assert.equal(aclMutations, 0);
    assert.deepEqual(fs.readdirSync(target), []);
  });

  it("requires one exact native Codex task, saved project, and cwd", async () => {
    const cwd = root(); const taskId = crypto.randomUUID(); const projectId = crypto.randomUUID();
    const calls = [];
    const relay = { async requestDesktop(operation, args, options) { calls.push(operation); options.beforeSend(); if (operation === "list_projects") return { result: { projects: [{ projectId, projectKind: "local", hostId: "local", path: cwd }] } }; if (operation === "read_thread") return { result: { thread: { id: taskId, hostId: "local", cwd } } }; return { result: { pinnedThreads: [], threads: [{ id: taskId, hostId: "local", projectId, cwd }] } }; } };
    const identity = { claude: "a", codex: "b" }; let checks = 0;
    await inspectCodexTask({ codexTaskId: taskId, projectId, canonicalCwd: cwd, accountIdentity: identity, relay, assertAccounts: (value) => { assert.deepEqual(value, identity); checks += 1; } });
    assert.deepEqual(calls, ["list_projects", "read_thread", "list_threads"]); assert.equal(checks, 3);
    const wrong = { ...relay, async requestDesktop(operation, args, options) { const response = await relay.requestDesktop(operation, args, options); if (operation === "list_threads") response.result.threads[0].projectId = crypto.randomUUID(); return response; } };
    await assert.rejects(inspectCodexTask({ codexTaskId: taskId, projectId, canonicalCwd: cwd, accountIdentity: identity, relay: wrong, assertAccounts: () => {} }), /does not match/);
  });

  it("accepts the real local_ Claude task-id shape but writes nothing before native preflight", async () => {
    const cwd = root(); const setupRoot = path.join(cwd, "auth");
    const accounts = { claude: { status: "verified", fingerprint: "a" }, codex: { status: "verified", fingerprint: "b" } };
    await assert.rejects(provisionPeerAuth({ root: setupRoot, cwd, projectId: crypto.randomUUID(), claudeTaskId: `local_${crypto.randomUUID()}`, claudeSessionId: "session", codexTaskId: crypto.randomUUID(), accounts, sessions: [] }), /missing or ambiguous/);
    assert.equal(fs.existsSync(setupRoot), false);
  });
});

describe("peer authentication Claude prompt origin", () => {
  it("distinguishes a human root from an exact peer marker and ignores tool-result users", () => {
    const home = root(); const previousHome = process.env.HOME; process.env.HOME = home;
    try {
      const cwd = path.join(home, "work"); fs.mkdirSync(cwd);
      const directory = path.join(home, ".claude", "projects", "fixture"); fs.mkdirSync(directory, { recursive: true });
      const sessionId = "session"; const file = path.join(directory, `${sessionId}.jsonl`); const messageId = crypto.randomUUID();
      const rows = [
        { uuid: "human", promptId: "human-turn", origin: { kind: "human" }, message: { role: "user", content: "root" } },
        { uuid: messageId, promptId: "peer-turn", origin: { kind: "peer", msg_id: messageId, from: "uds:test" }, message: { role: "user", content: `[codex-claude-peer-auth/1 message_id=${messageId}]` } },
        { uuid: "tool", promptId: "peer-turn", message: { role: "user", content: [{ type: "tool_result", content: "ok" }] } },
      ];
      fs.writeFileSync(file, `${rows.map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "peer-turn", origin: "peer", peerMessageId: messageId });
      rows.splice(1); fs.writeFileSync(file, `${rows.map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "human-turn", origin: "human", peerMessageId: null });
    } finally { if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome; }
  });
});
