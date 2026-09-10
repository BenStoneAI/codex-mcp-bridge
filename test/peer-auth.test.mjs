import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { canonicalPeerEnvelope, peerPayloadHash, signPeerEnvelope } from "../src/peer-auth-canonical.mjs";
import { PeerAuthKeyStore } from "../src/peer-auth-keystore-win32.mjs";
import { PeerAuthService } from "../src/peer-auth-service.mjs";
import { PeerAuthStore } from "../src/peer-auth-store.mjs";

const CWD_ID = "1048576:12345";
const PROJECT = "bridge-safety-lab";

function protectedBytes(bytes) { return Buffer.from(bytes.map((byte) => byte ^ 0xa5)); }
function fixture(t, { now = 1_800_000_000_000, randomBytes } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "peer-auth-"));
  fs.mkdirSync(path.join(root, "project"));
  const cwd = fs.realpathSync.native(path.join(root, "project"));
  const keyRoot = path.join(root, "auth");
  const keyStore = new PeerAuthKeyStore({ root: keyRoot, platform: "win32", protect: protectedBytes, unprotect: protectedBytes, protectAcl: () => {}, validateAcl: () => {} });
  keyStore.setup();
  const store = new PeerAuthStore({ root: keyRoot, validateStorage: () => {}, now: () => now });
  t.after(() => { try { store.close(); } catch {} fs.rmSync(root, { recursive: true, force: true }); });
  const claude = { agent: "claude", account_fingerprint: "claude-account", task_id: "claude-task", session_id: "claude-session", turn_id: "claude-turn", canonical_cwd: cwd, cwd_identity: CWD_ID, project_id: PROJECT, project_host_id: "local", allowed_roots: [cwd] };
  const codex = { agent: "codex", account_fingerprint: "codex-account", task_id: "codex-task", session_id: null, turn_id: "codex-turn", canonical_cwd: cwd, cwd_identity: CWD_ID, project_id: PROJECT, project_host_id: "local", allowed_roots: [cwd] };
  for (const identity of [claude, codex]) store.provisionGrant({ agent: identity.agent, accountFingerprint: identity.account_fingerprint, taskId: identity.task_id, sessionId: identity.session_id, cwd, cwdIdentity: CWD_ID, projectId: PROJECT, capabilityCeiling: "review_only" });
  const service = (agent, options = {}) => new PeerAuthService({ agent, store, keyStore, now: () => now, ...(randomBytes ? { randomBytes } : {}), ...options });
  const stable = (identity) => async () => structuredClone(identity);
  const issue = async ({ from = claude, to = codex, capability = "read_only", parentMessageId = null, transport = async () => {}, service: issuer = service(from.agent), text = "review this" } = {}) => issuer.issueRequest({
    text, sender: from, recipient: to, requestedCapability: capability, parentMessageId,
    revalidateSender: stable(from), revalidateRecipient: stable(to), transport,
  });
  const verify = (messageId, { recipient = codex, sender = claude, service: verifier = service(recipient.agent), revalidateRecipient = stable(recipient) } = {}) => verifier.verifyPeerMessage({ messageId, recipient, revalidateRecipient, resolveSender: stable(sender) });
  return { root, keyRoot, cwd, keyStore, store, claude, codex, service, stable, issue, verify, now: () => now };
}

function rewriteEnvelope(f, messageId, mutate, { resignAgent } = {}) {
  const row = f.store.get(messageId);
  const envelope = JSON.parse(row.envelopeJson);
  mutate(envelope);
  const envelopeJson = canonicalPeerEnvelope(envelope);
  const signature = resignAgent ? f.keyStore.withPrivateIdentity(resignAgent, ({ privateKey }) => signPeerEnvelope(envelope, privateKey)) : row.signature;
  f.store.db.prepare("UPDATE messages SET envelope_json=?,envelope_sha256=?,signature=?,signer_key_id=? WHERE message_id=?").run(
    envelopeJson, crypto.createHash("sha256").update(envelopeJson).digest("hex"), signature, envelope.signer_key_id, messageId,
  );
}

describe("authenticated peer messages", () => {
  for (const direction of ["claude_to_codex", "codex_to_claude"]) {
    it(`accepts a valid signed ${direction} request`, async (t) => {
      const f = fixture(t);
      const from = direction.startsWith("claude") ? f.claude : f.codex;
      const to = from === f.claude ? f.codex : f.claude;
      const issued = await f.issue({ from, to });
      const verified = await f.verify(issued.message_id, { recipient: to, sender: from });
      assert.equal(verified.status, "VERIFIED");
      assert.equal(verified.payload.text, "review this");
      assert.equal(verified.sender.task_id, from.task_id);
      assert.equal(verified.recipient.task_id, to.task_id);
    });
  }

  it("rejects altered prompt and capability without accepting either signature", async (t) => {
    for (const field of ["prompt", "capability"]) {
      const f = fixture(t);
      const issued = await f.issue();
      rewriteEnvelope(f, issued.message_id, (envelope) => {
        if (field === "prompt") { envelope.payload.text = "altered"; envelope.payload.sha256 = peerPayloadHash("altered"); }
        else envelope.requested_capability = "review_only";
      });
      assert.equal((await f.verify(issued.message_id)).status, "INVALID_SIGNATURE");
    }
  });

  it("rejects a forged sender and an unknown public key", async (t) => {
    for (const unknown of [false, true]) {
      const f = fixture(t);
      const issued = await f.issue();
      rewriteEnvelope(f, issued.message_id, (envelope) => {
        if (unknown) envelope.signer_key_id = "f".repeat(64);
      }, { resignAgent: unknown ? undefined : "codex" });
      assert.equal((await f.verify(issued.message_id)).status, unknown ? "UNKNOWN_SIGNER" : "INVALID_SIGNATURE");
    }
  });

  it("rejects every changed native sender or recipient identity field", async (t) => {
    const cases = [
      ["sender task", "WRONG_TASK", (f) => ({ sender: { ...f.claude, task_id: "wrong" } })],
      ["recipient task", "WRONG_TASK", (f) => ({ recipient: { ...f.codex, task_id: "wrong" } })],
      ["sender session", "WRONG_SESSION", (f) => ({ sender: { ...f.claude, session_id: "wrong" } })],
      ["recipient session", "WRONG_SESSION", (f) => ({ recipient: { ...f.codex, session_id: "wrong" } })],
      ["cwd", "WRONG_CWD", (f) => ({ recipient: { ...f.codex, canonical_cwd: f.root } })],
      ["project", "WRONG_PROJECT", (f) => ({ recipient: { ...f.codex, project_id: "wrong" } })],
      ["account", "WRONG_ACCOUNT", (f) => ({ recipient: { ...f.codex, account_fingerprint: "wrong" } })],
    ];
    for (const [label, status, change] of cases) await t.test(label, async (t2) => {
      const f = fixture(t2);
      const issued = await f.issue();
      const changed = change(f);
      const result = await f.verify(issued.message_id, { ...(changed.sender ? { sender: changed.sender } : {}), ...(changed.recipient ? { recipient: changed.recipient, revalidateRecipient: f.stable(changed.recipient) } : {}) });
      assert.equal(result.status, status);
    });
  });

  it("rejects expired and replayed requests", async (t) => {
    let now = 1_800_000_000_000;
    const f = fixture(t, { now });
    const service = new PeerAuthService({ agent: "claude", store: f.store, keyStore: f.keyStore, now: () => now, ttlMs: 1000 });
    const issued = await f.issue({ service });
    now += 1001;
    const verifier = new PeerAuthService({ agent: "codex", store: f.store, keyStore: f.keyStore, now: () => now });
    assert.equal((await f.verify(issued.message_id, { service: verifier })).status, "EXPIRED");
    const f2 = fixture(t);
    const second = await f2.issue();
    assert.equal((await f2.verify(second.message_id)).status, "VERIFIED");
    assert.equal((await f2.verify(second.message_id)).status, "REPLAY");
  });

  it("rejects nonce reuse transactionally", async (t) => {
    const f = fixture(t, { randomBytes: () => Buffer.alloc(32, 7) });
    await f.issue();
    await assert.rejects(f.issue(), (error) => error.code === "NONCE_REUSE");
    assert.equal(f.store.count(), 1);
  });

  it("creates one receiver-signed reply and returns it only to the exact origin", async (t) => {
    const f = fixture(t);
    const request = await f.issue();
    assert.equal((await f.verify(request.message_id)).status, "VERIFIED");
    const codex = f.service("codex");
    const reply = await codex.replyToPeerMessage({ parentMessageId: request.message_id, text: "review complete", sender: f.codex, revalidateSender: f.stable(f.codex), resolveRecipient: f.stable(f.claude) });
    const replyRow = f.store.get(reply.message_id);
    assert.equal(replyRow.signerKeyId, f.keyStore.publicIdentity("codex").keyId);
    await assert.rejects(codex.replyToPeerMessage({ parentMessageId: crypto.randomUUID(), text: "wrong", sender: f.codex, revalidateSender: f.stable(f.codex) }), (error) => error.code === "INVALID_PARENT");
    const read = await f.service("claude").readPeerReply({ messageId: request.message_id, origin: f.claude, revalidateOrigin: f.stable(f.claude), resolveReplySender: f.stable(f.codex) });
    assert.equal(read.status, "VERIFIED"); assert.equal(read.payload.text, "review complete");
    const redirected = await f.service("claude").readPeerReply({ messageId: request.message_id, origin: { ...f.claude, task_id: "redirect" }, revalidateOrigin: f.stable({ ...f.claude, task_id: "redirect" }), resolveReplySender: f.stable(f.codex) });
    assert.equal(redirected.status, "WRONG_TASK");
  });

  it("rejects child privilege escalation and omitted parent escape", async (t) => {
    const f = fixture(t);
    const request = await f.issue({ capability: "read_only" });
    assert.equal((await f.verify(request.message_id)).status, "VERIFIED");
    const childService = f.service("codex");
    await assert.rejects(f.issue({ from: f.codex, to: f.claude, capability: "review_only", parentMessageId: request.message_id, service: childService }), (error) => error.code === "CAPABILITY_DENIED");
    await assert.rejects(f.issue({ from: f.codex, to: f.claude, service: childService }), (error) => error.code === "INVALID_PARENT");
  });

  it("fails closed on an account switch or ambiguous helper identity", async (t) => {
    const f = fixture(t);
    const request = await f.issue();
    const switched = { ...f.codex, account_fingerprint: "switched" };
    assert.equal((await f.verify(request.message_id, { recipient: f.codex, revalidateRecipient: f.stable(switched) })).status, "WRONG_ACCOUNT");
    const f2 = fixture(t);
    const request2 = await f2.issue();
    assert.equal((await f2.verify(request2.message_id, { revalidateRecipient: async () => { throw new Error("ambiguous helper process"); } })).status, "UNVERIFIED");
  });

  it("persists replay state across a safe store reconnect", async (t) => {
    const f = fixture(t);
    const request = await f.issue();
    assert.equal((await f.verify(request.message_id)).status, "VERIFIED");
    f.store.close();
    const reopened = new PeerAuthStore({ root: f.keyRoot, validateStorage: () => {}, now: f.now });
    const verifier = new PeerAuthService({ agent: "codex", store: reopened, keyStore: f.keyStore, now: f.now });
    assert.equal((await verifier.verifyPeerMessage({ messageId: request.message_id, recipient: f.codex, revalidateRecipient: f.stable(f.codex), resolveSender: f.stable(f.claude) })).status, "REPLAY");
    reopened.close();
  });

  it("never retries uncertain delivery or places payload/private material in the transport marker", async (t) => {
    const f = fixture(t);
    let attempts = 0; let marker;
    await assert.rejects(f.issue({ text: "sensitive request", transport: async (input) => { attempts += 1; marker = input.marker; throw new Error("lost ack"); } }), (error) => error.code === "DELIVERY_UNKNOWN");
    assert.equal(attempts, 1);
    assert.doesNotMatch(marker, /sensitive request|PRIVATE KEY/);
    assert.equal(f.store.db.prepare("SELECT state FROM messages").get().state, "delivery_unknown");
  });
});
