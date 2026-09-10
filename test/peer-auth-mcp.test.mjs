import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { z } from "zod";
import { PeerAuthStore } from "../src/peer-auth-store.mjs";
import { PeerAuthService } from "../src/peer-auth-service.mjs";
import { registerPeerAuthTools } from "../src/peer-auth-mcp.mjs";

const roots = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "peer-auth-mcp-")); roots.push(root);
  const pairs = Object.fromEntries(["claude", "codex"].map((agent) => [agent, crypto.generateKeyPairSync("ed25519")]));
  const keyStore = {
    publicIdentity(agent) { const publicKey = pairs[agent].publicKey; return { publicKey, keyId: crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex") }; },
    withPrivateIdentity(agent, callback) { return callback({ privateKey: pairs[agent].privateKey, keyId: this.publicIdentity(agent).keyId }); },
  };
  const store = new PeerAuthStore({ root });
  const cwd = fs.realpathSync.native(root); const stat = fs.statSync(cwd, { bigint: true }); const cwdIdentity = `${stat.dev}:${stat.ino}`;
  const identity = (agent) => ({ agent, account_fingerprint: `${agent}-account`, task_id: `${agent}-task`, session_id: agent === "claude" ? "claude-session" : null, turn_id: `${agent}-turn`, canonical_cwd: cwd, cwd_identity: cwdIdentity, project_id: "project", project_host_id: "local", allowed_roots: [cwd] });
  const claude = identity("claude"); const codex = identity("codex");
  for (const value of [claude, codex]) store.provisionGrant({ agent: value.agent, accountFingerprint: value.account_fingerprint, taskId: value.task_id, sessionId: value.session_id, cwd, cwdIdentity, projectId: "project", capabilityCeiling: "review_only" });
  return { store, claude, codex, services: { claude: new PeerAuthService({ agent: "claude", store, keyStore }), codex: new PeerAuthService({ agent: "codex", store, keyStore }) } };
}

function tools(runtime, currentIdentity, resolvePeerIdentity) {
  const registered = new Map();
  registerPeerAuthTools({ registerTool: (name, definition, handler) => registered.set(name, { definition, handler }), z, runtime, currentIdentity, resolvePeerIdentity });
  return registered;
}

describe("peer authentication MCP handlers", () => {
  for (const [from, to] of [["claude", "codex"], ["codex", "claude"]]) it(`verifies and closes one exact ${from} to ${to} signed exchange`, async () => {
    const f = fixture();
    const sender = f[from]; const recipient = f[to];
    const request = await f.services[from].issueRequest({ text: "review", sender, recipient, revalidateSender: async () => sender, revalidateRecipient: async () => recipient, transport: async () => {} });
    const current = { identity: recipient, nativeOrigin: "peer", peerMessageId: request.message_id };
    const recipientTools = tools({ service: f.services[to] }, async () => current, async (_endpoint, _extra, envelope) => ({ ...sender, turn_id: envelope.sender.turn_id }));
    assert.deepEqual([...recipientTools.keys()], ["verify_peer_message", "reply_to_peer_message", "read_peer_reply"]);
    const verified = await recipientTools.get("verify_peer_message").handler({ message_id: request.message_id }, {});
    assert.equal(verified.structuredContent.peerAuth.status, "VERIFIED");
    assert.equal(verified.structuredContent.peerAuth.payload.text, "review");
    const reply = await recipientTools.get("reply_to_peer_message").handler({ parent_message_id: request.message_id, text: "done" }, {});
    assert.equal(reply.structuredContent.peerAuth.status, "REPLY_SIGNED");
    const originTools = tools({ service: f.services[from] }, async () => ({ identity: sender, nativeOrigin: "human", peerMessageId: null }), async () => recipient);
    const read = await originTools.get("read_peer_reply").handler({ message_id: request.message_id }, {});
    assert.equal(read.structuredContent.peerAuth.status, "VERIFIED");
    assert.equal(read.structuredContent.peerAuth.payload.text, "done");
    assert.doesNotMatch(JSON.stringify([verified, reply, read]), /private|pkcs8/i);
    f.store.close();
  });

  it("does not consume without exact native marker correlation and fails if the marker changes", async () => {
    const f = fixture();
    const request = await f.services.claude.issueRequest({ text: "review", sender: f.claude, recipient: f.codex, revalidateSender: async () => f.claude, revalidateRecipient: async () => f.codex, transport: async () => {} });
    let current = { identity: f.codex, nativeOrigin: "human", peerMessageId: null };
    const registered = tools({ service: f.services.codex }, async () => current, async () => f.claude);
    const absent = await registered.get("verify_peer_message").handler({ message_id: request.message_id }, {});
    assert.equal(absent.structuredContent.peerAuth.status, "UNVERIFIED");
    assert.equal(f.store.get(request.message_id).state, "dispatch_confirmed");
    let reads = 0;
    current = { identity: f.codex, nativeOrigin: "peer", peerMessageId: request.message_id };
    const drifting = tools({ service: f.services.codex }, async () => (++reads === 1 ? current : { ...current, peerMessageId: crypto.randomUUID() }), async () => f.claude);
    const refused = await drifting.get("verify_peer_message").handler({ message_id: request.message_id }, {});
    assert.notEqual(refused.structuredContent.peerAuth.status, "VERIFIED");
    assert.equal(f.store.get(request.message_id).state, "dispatch_confirmed");
    f.store.close();
  });
});
