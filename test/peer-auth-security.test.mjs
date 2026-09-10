import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { buildPeerEnvelope, capabilityAllows, signPeerEnvelope, validatePeerEnvelope, verifyPeerEnvelopeSignature } from "../src/peer-auth-canonical.mjs";
import { inspectCodexNativePeerTurn } from "../src/codex-native-response.mjs";
import { PeerAuthKeyStore } from "../src/peer-auth-keystore-win32.mjs";
import { PeerAuthStore } from "../src/peer-auth-store.mjs";
import { inspectCodexTask, provisionPeerAuth } from "../src/peer-auth-setup.mjs";
import { readClaudePromptContext } from "../src/peer-protocol.mjs";
import { readCodexSenderContext } from "../src/codex-sender-context.mjs";

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
    fs.symlinkSync(target, junction, "junction");
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

describe("peer authentication Codex issuer lifecycle", () => {
  it("accepts one exact active or completed native issuer turn and rejects malformed lifecycle evidence", () => {
    const home = root(); const cwd = path.join(home, "work"); fs.mkdirSync(cwd);
    const directory = path.join(home, ".codex", "sessions", "2026", "09", "09"); fs.mkdirSync(directory, { recursive: true });
    const threadId = crypto.randomUUID(); const turnId = crypto.randomUUID(); const otherTurn = crypto.randomUUID();
    const file = path.join(directory, `rollout-auth-${threadId}.jsonl`);
    const session = { type: "session_meta", payload: { id: threadId, originator: "Codex Desktop", source: "vscode", cwd } };
    const start = { type: "event_msg", payload: { type: "task_started", turn_id: turnId } };
    const context = { type: "turn_context", payload: { turn_id: turnId, cwd } };
    const complete = { type: "event_msg", payload: { type: "task_complete", turn_id: turnId } };
    const write = (records, first = session) => fs.writeFileSync(file, `${[first, ...records].map(JSON.stringify).join("\n")}\n`);
    const inspect = (overrides = {}) => inspectCodexNativePeerTurn({ threadId, turnId, expectedCwd: cwd, ...overrides }, { env: { HOME: home, USERPROFILE: home, CODEX_HOME: path.join(home, ".codex") } });

    write([start, context]);
    assert.deepEqual(inspect(), { status: "active", threadId, turnId, source: "codex_desktop_rollout" });
    write([start, context, complete]);
    assert.deepEqual(inspect(), { status: "completed", threadId, turnId, source: "codex_desktop_rollout" });

    const invalid = [
      ["aborted", [start, context, { type: "event_msg", payload: { type: "turn_aborted", turn_id: turnId } }]],
      ["failed", [start, context, { type: "event_msg", payload: { type: "turn_failed", turn_id: turnId } }]],
      ["duplicate start", [start, start, context]],
      ["duplicate context", [start, context, context]],
      ["duplicate completion", [start, context, complete, complete]],
      ["out of order", [context, start]],
      ["missing turn", [{ type: "event_msg", payload: { type: "task_started", turn_id: otherTurn } }, { type: "turn_context", payload: { turn_id: otherTurn, cwd } }]],
      ["wrong cwd", [start, { ...context, payload: { ...context.payload, cwd: home } }]],
      ["superseded active turn", [start, context, { type: "event_msg", payload: { type: "task_started", turn_id: otherTurn } }]],
      ["contradictory turn", [{ ...start, payload: { ...start.payload, root_turn_id: otherTurn } }, context]],
    ];
    for (const [name, records] of invalid) { write(records); assert.equal(inspect().status, "unavailable", name); }
    write([start, context], { ...session, payload: { ...session.payload, source: "cli" } });
    assert.equal(inspect().status, "unavailable", "wrong source");
    write([start, context], { ...session, payload: { ...session.payload, id: crypto.randomUUID() } });
    assert.equal(inspect().status, "unavailable", "wrong task");
  });
});

describe("peer authentication Claude prompt origin", () => {
  it("accepts the native meta peer shape without allowing unsupported peer records to fall back to a human root", () => {
    const home = root(); const previousHome = process.env.HOME; process.env.HOME = home;
    try {
      const cwd = path.join(home, "work"); fs.mkdirSync(cwd);
      const directory = path.join(home, ".claude", "projects", "fixture"); fs.mkdirSync(directory, { recursive: true });
      const sessionId = "session"; const file = path.join(directory, `${sessionId}.jsonl`); const messageId = crypto.randomUUID();
      const human = { uuid: "human", promptId: "human-turn", origin: { kind: "human" }, message: { role: "user", content: "root" } };
      const peer = {
        type: "user", isMeta: true, isSidechain: false, uuid: messageId, promptId: "peer-turn", entrypoint: "claude-desktop", cwd, sessionId,
        origin: { kind: "peer", from: "uds:test", msg_id: messageId, fromMode: "bypass", body: "opaque" },
        message: { role: "user", content: `[codex-claude-peer-auth/1 message_id=${messageId}]` },
      };
      const rows = [
        human,
        peer,
        { uuid: "tool", promptId: "peer-turn", message: { role: "user", content: [{ type: "tool_result", content: "ok" }] } },
      ];
      fs.writeFileSync(file, `${rows.map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "peer-turn", origin: "peer", peerMessageId: messageId });

      fs.writeFileSync(file, `${[human, { ...peer, message: { role: "user", content: "unsigned opaque peer payload" } }].map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "peer-turn", origin: "peer", peerMessageId: messageId });

      fs.writeFileSync(file, `${[human, { ...peer, uuid: crypto.randomUUID() }].map(JSON.stringify).join("\n")}\n`);
      assert.throws(() => readClaudePromptContext(sessionId, cwd), /does not match/);

      const ordinaryMeta = { uuid: "meta", promptId: "meta-turn", isMeta: true, message: { role: "user", content: "ordinary metadata" } };
      fs.writeFileSync(file, `${[human, ordinaryMeta].map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "human-turn", origin: "human", peerMessageId: null });

      const queuedPeer = { uuid: "queue", type: "attachment", attachment: { type: "queued_command", source_uuid: "unrelated", origin: { kind: "peer", msg_id: messageId, fromMode: "bypass" }, isMeta: true } };
      fs.writeFileSync(file, `${[human, queuedPeer].map(JSON.stringify).join("\n")}\n`);
      assert.throws(() => readClaudePromptContext(sessionId, cwd), /queued peer prompt/i);

      const laterHuman = { uuid: "later", promptId: "later-turn", origin: { kind: "human" }, message: { role: "user", content: "next root" } };
      fs.writeFileSync(file, `${[human, ordinaryMeta, laterHuman].map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "later-turn", origin: "human", peerMessageId: null });

      fs.writeFileSync(file, `${[human, queuedPeer, laterHuman].map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "later-turn", origin: "human", peerMessageId: null });
      fs.writeFileSync(file, `${[human, queuedPeer, peer].map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "peer-turn", origin: "peer", peerMessageId: messageId });
      fs.writeFileSync(file, `${[human, { ...peer, uuid: crypto.randomUUID() }, laterHuman].map(JSON.stringify).join("\n")}\n`);
      assert.deepEqual(readClaudePromptContext(sessionId, cwd), { turnId: "later-turn", origin: "human", peerMessageId: null });
    } finally { if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome; }
  });
});

it("rejects mixed native peer ancestry while preserving signed-only and unsigned-only classification", () => {
  for (const kinds of [["signed"], ["unsigned"], ["signed", "unsigned"], ["unsigned", "signed"]]) {
    const home = root(); const threadId = crypto.randomUUID(); const turnId = crypto.randomUUID(); const messageId = crypto.randomUUID();
    const directory = path.join(home, "sessions", "2026", "09", "09"); fs.mkdirSync(directory, { recursive: true });
    const records = [
      { type: "session_meta", payload: { id: threadId, originator: "Codex Desktop", source: "vscode", cwd: home } },
      { type: "event_msg", payload: { type: "task_started", turn_id: turnId } },
      { type: "turn_context", payload: { turn_id: turnId, cwd: home, approval_policy: "never", approvals_reviewer: "user", permission_profile: { type: "disabled" }, sandbox_policy: { type: "danger-full-access" } } },
      ...kinds.map((kind) => ({ type: "response_item", payload: { type: "function_call_output", name: "send_message_to_thread", namespace: "codex_app", output: `<codex_delegation>\n  <source_thread_id>source</source_thread_id>\n  <input>${kind === "signed" ? `[codex-claude-peer-auth/1 message_id=${messageId}]` : "unsigned peer text"}</input>\n</codex_delegation>`, internal_chat_message_metadata_passthrough: { turn_id: turnId } } })),
    ];
    fs.writeFileSync(path.join(directory, `rollout-security-${threadId}.jsonl`), `${records.map(JSON.stringify).join("\n")}\n`);
    const metadata = { "x-codex-turn-metadata": { thread_id: threadId, turn_id: turnId, thread_source: "user", auto_review_enabled: false, node_repl_auto_review_required: false } };
    const result = readCodexSenderContext(metadata, { env: { CODEX_HOME: home, CODEX_BRIDGE_PEER_AUTH: "1" } });
    assert.equal(result.status, kinds.length > 1 ? "unavailable" : "verified", kinds.join("+"));
    if (kinds.length === 1) { assert.equal(result.nativeOrigin, "peer"); assert.equal(result.peerMessageId, kinds[0] === "signed" ? messageId : null); }
    assert.equal(readCodexSenderContext(metadata, { env: { CODEX_HOME: home } }).status, "verified", "Authentication opt-out retains the raw caller contract");
  }
});
