import crypto from "node:crypto";
import path from "node:path";
import {
  canonicalPeerEnvelope, capabilityAllows, peerPayloadHash, signPeerEnvelope,
  validatePeerEnvelope, verifyPeerEnvelopeSignature,
} from "./peer-auth-canonical.mjs";

const MAX_TTL_MS = 15 * 60 * 1000;
const CLOCK_SKEW_MS = 60 * 1000;
const SAFE_STATUSES = new Set(["VERIFIED", "INVALID_SIGNATURE", "UNKNOWN_SIGNER", "WRONG_ACCOUNT", "WRONG_TASK", "WRONG_SESSION", "WRONG_PROJECT", "WRONG_CWD", "EXPIRED", "REPLAY", "NONCE_REUSE", "INVALID_PARENT", "CAPABILITY_DENIED", "MALFORMED", "DELIVERY_UNKNOWN", "UNVERIFIED"]);

function authError(code, message) { return Object.assign(new Error(message), { code }); }
function publicFailure(messageId, code) { return { status: SAFE_STATUSES.has(code) ? code : "UNVERIFIED", message_id: messageId, reason_code: SAFE_STATUSES.has(code) ? code : "UNVERIFIED" }; }
function exactIdentity(expected, current, { includeTurn = true } = {}) {
  for (const field of ["agent", "account_fingerprint", "task_id", "session_id", "turn_id", "canonical_cwd", "cwd_identity", "project_id", "project_host_id"]) {
    if (field === "turn_id" && !includeTurn) continue;
    if ((expected?.[field] ?? null) !== (current?.[field] ?? null)) return field;
  }
  if (expected && Object.hasOwn(expected, "allowed_roots") && JSON.stringify(expected.allowed_roots) !== JSON.stringify(current?.allowed_roots ?? null)) return "allowed_roots";
  return null;
}
function identityCode(field) {
  if (field === "account_fingerprint") return "WRONG_ACCOUNT";
  if (field === "task_id" || field === "turn_id" || field === "agent") return "WRONG_TASK";
  if (field === "session_id") return "WRONG_SESSION";
  if (field === "project_id" || field === "project_host_id") return "WRONG_PROJECT";
  if (field === "canonical_cwd" || field === "cwd_identity") return "WRONG_CWD";
  return "UNVERIFIED";
}
function endpoint(identity, sender = false) {
  return {
    agent: identity.agent,
    account_fingerprint: identity.account_fingerprint,
    task_id: identity.task_id,
    session_id: identity.session_id ?? null,
    ...(sender ? { turn_id: identity.turn_id ?? null } : {}),
  };
}
function scoped(identity, envelope) {
  return { ...endpoint(identity, true), canonical_cwd: envelope.scope.canonical_cwd, cwd_identity: envelope.scope.cwd_identity, project_id: envelope.scope.project_id, project_host_id: envelope.scope.project_host_id };
}
function canonicalPathEqual(first, second) { return path.relative(first, second) === ""; }
function rootWithin(cwd, root) {
  const relative = path.relative(cwd, root);
  return relative === "" || (relative && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}
function rootsPermit(signedRoots, identity) {
  return signedRoots.every((root) => identity.allowed_roots.some((allowed) => rootWithin(allowed, root)));
}

export function peerAuthMarker(messageId) { return `[codex-claude-peer-auth/1 message_id=${messageId}]`; }

export class PeerAuthService {
  constructor({ agent, store, keyStore, now = Date.now, randomUUID = crypto.randomUUID, randomBytes = crypto.randomBytes, ttlMs = MAX_TTL_MS, log = () => {} } = {}) {
    if (!new Set(["claude", "codex"]).has(agent) || !store || !keyStore) throw new Error("Peer authentication service configuration is invalid");
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > MAX_TTL_MS) throw new Error("Peer authentication TTL is invalid");
    this.agent = agent; this.store = store; this.keyStore = keyStore; this.now = now; this.randomUUID = randomUUID; this.randomBytes = randomBytes; this.ttlMs = ttlMs; this.log = log;
  }

  #assertIdentity(identity, agent = identity?.agent) {
    if (!identity || identity.agent !== agent || !identity.account_fingerprint || !identity.task_id || !identity.canonical_cwd || !path.isAbsolute(identity.canonical_cwd) ||
        !identity.cwd_identity || !identity.project_id || identity.project_host_id !== "local" || !Array.isArray(identity.allowed_roots) || !identity.allowed_roots.length ||
        identity.allowed_roots.some((root) => !path.isAbsolute(root) || !rootWithin(identity.canonical_cwd, root))) throw authError("UNVERIFIED", "Native peer identity is incomplete or outside its signed scope");
    return identity;
  }

  async #stable(identity, revalidate) {
    this.#assertIdentity(identity);
    if (typeof revalidate !== "function") throw authError("UNVERIFIED", "Native identity revalidation is unavailable");
    const current = this.#assertIdentity(await revalidate());
    const mismatch = exactIdentity(identity, current);
    if (mismatch) throw authError(identityCode(mismatch), "Native peer identity changed");
    return current;
  }

  #signed(envelope) {
    const envelopeJson = canonicalPeerEnvelope(envelope);
    const envelopeSha256 = crypto.createHash("sha256").update(envelopeJson, "utf8").digest("hex");
    return this.keyStore.withPrivateIdentity(this.agent, ({ privateKey }) => ({ envelopeJson, envelopeSha256, signature: signPeerEnvelope(envelope, privateKey) }));
  }

  #envelope({ kind, text, sender, recipient, capability, parentMessageId, originTaskId, scope, allowedRoots }) {
    const issuedAt = this.now();
    const own = this.keyStore.publicIdentity(this.agent);
    return {
      protocol: "codex-claude-peer-auth/1", kind, message_id: this.randomUUID(), parent_message_id: parentMessageId,
      nonce: this.randomBytes(32).toString("base64url"), issued_at: issuedAt, expires_at: issuedAt + this.ttlMs,
      sender: endpoint(sender, true), recipient: endpoint(recipient), scope,
      originating_user_task_id: originTaskId, requested_capability: capability,
      allowed_roots: [...allowedRoots].sort(),
      payload: { media_type: "text/plain; charset=utf-8", text, sha256: peerPayloadHash(text) }, signer_key_id: own.keyId,
    };
  }

  #grant(identity) {
    const grant = this.store.grantFor(identity);
    if (!grant) throw authError("CAPABILITY_DENIED", "No enabled local peer grant matches the exact native task and project");
    if ((grant.session_id || "") !== (identity.session_id ?? "")) throw authError("WRONG_SESSION", "The local peer grant no longer matches the native session identity");
    if (grant.cwd_identity !== identity.cwd_identity) throw authError("WRONG_CWD", "The local peer grant no longer matches the directory identity");
    return grant;
  }

  #assertVerifiedParentChain(messageId, now = this.now(), seen = new Set()) {
    if (seen.size >= 32 || seen.has(messageId)) throw authError("INVALID_PARENT", "Peer parent chain is cyclic or too deep");
    seen.add(messageId);
    const verified = this.#readVerifiedRow(messageId);
    if (!verified.row || !["consumed", "replied"].includes(verified.row.state)) throw authError("INVALID_PARENT", "Peer parent is unavailable or unconsumed");
    if (now > verified.envelope.expires_at || verified.envelope.issued_at > now + CLOCK_SKEW_MS) throw authError("EXPIRED", "Peer parent is expired or from the future");
    if (verified.envelope.parent_message_id) {
      const ancestor = this.#assertVerifiedParentChain(verified.envelope.parent_message_id, now, seen);
      const child = verified.envelope;
      const senderMismatch = exactIdentity(scoped(child.sender, child), scoped(ancestor.recipient, ancestor), { includeTurn: false });
      const recipientMismatch = exactIdentity(scoped(child.recipient, child), scoped(ancestor.sender, ancestor), { includeTurn: false });
      if (senderMismatch || recipientMismatch || child.originating_user_task_id !== ancestor.originating_user_task_id ||
          JSON.stringify(child.scope) !== JSON.stringify(ancestor.scope) || JSON.stringify(child.allowed_roots) !== JSON.stringify(ancestor.allowed_roots) ||
          !capabilityAllows(ancestor.requested_capability, child.requested_capability)) throw authError("INVALID_PARENT", "Peer parent chain changed route or authority");
    }
    return verified.envelope;
  }

  async issueRequest({ text, sender, recipient, requestedCapability = "read_only", parentMessageId = null, revalidateSender, revalidateRecipient, transport }) {
    try {
      if (typeof text !== "string" || text !== text.normalize("NFC")) throw authError("MALFORMED", "Peer request text must already be NFC");
      this.#assertIdentity(sender, this.agent); this.#assertIdentity(recipient, this.agent === "claude" ? "codex" : "claude");
      if (!canonicalPathEqual(sender.canonical_cwd, recipient.canonical_cwd) || sender.cwd_identity !== recipient.cwd_identity || sender.project_id !== recipient.project_id) throw authError("WRONG_PROJECT", "Peer endpoints do not share the exact project scope");
      await this.#stable(sender, revalidateSender); await this.#stable(recipient, revalidateRecipient);
      const grant = this.#grant(sender);
      const recipientGrant = this.#grant(recipient);
      let ceiling = grant.capability_ceiling;
      let originTaskId = sender.task_id;
      let scope = { canonical_cwd: sender.canonical_cwd, cwd_identity: sender.cwd_identity, project_id: sender.project_id, project_host_id: sender.project_host_id };
      let allowedRoots = sender.allowed_roots;
      const contexts = this.store.contextsFor(sender);
      if (!parentMessageId && contexts.length) throw authError("INVALID_PARENT", "An active peer-derived turn requires its exact consumed parent");
      if (parentMessageId && (contexts.length > 1 || contexts.length === 1 && (contexts[0].message_id !== parentMessageId || contexts[0].expires_at < this.now()))) throw authError("INVALID_PARENT", "The active peer-derived turn does not match the supplied parent context");
      if (parentMessageId) {
        const parentEnvelope = this.#assertVerifiedParentChain(parentMessageId);
        const mismatch = exactIdentity(scoped(parentEnvelope.recipient, parentEnvelope), sender, { includeTurn: false });
        if (mismatch || exactIdentity(scoped(parentEnvelope.sender, parentEnvelope), recipient, { includeTurn: false })) throw authError("INVALID_PARENT", "The delegated parent route does not match the current native endpoints");
        ceiling = parentEnvelope.requested_capability; originTaskId = parentEnvelope.originating_user_task_id; scope = parentEnvelope.scope; allowedRoots = parentEnvelope.allowed_roots;
      }
      if (!rootsPermit(allowedRoots, sender) || !rootsPermit(allowedRoots, recipient)) throw authError("WRONG_CWD", "Signed roots exceed the current native endpoints");
      if (!capabilityAllows(grant.capability_ceiling, requestedCapability) || !capabilityAllows(recipientGrant.capability_ceiling, requestedCapability) || !capabilityAllows(ceiling, requestedCapability)) throw authError("CAPABILITY_DENIED", "Requested peer capability exceeds the grant or parent");
      const envelope = this.#envelope({ kind: "request", text, sender, recipient, capability: requestedCapability, parentMessageId, originTaskId, scope, allowedRoots });
      const signed = this.#signed(envelope);
      const recipientKeyId = this.keyStore.publicIdentity(recipient.agent).keyId;
      try { this.store.issue({ ...signed, envelope, recipientKeyId, direction: `${sender.agent}_to_${recipient.agent}` }); }
      catch (error) { if (/nonce|UNIQUE/i.test(error.message)) throw authError("NONCE_REUSE", "Peer nonce was already issued"); throw error; }
      await this.#stable(sender, revalidateSender); await this.#stable(recipient, revalidateRecipient);
      this.store.markAttempt(envelope.message_id);
      try {
        if (typeof transport !== "function") throw new Error("Peer transport is unavailable");
        await transport({ marker: peerAuthMarker(envelope.message_id), messageId: envelope.message_id, recipient });
        this.store.markConfirmed(envelope.message_id);
      } catch (error) {
        this.store.markDeliveryUnknown(envelope.message_id);
        throw Object.assign(new Error("Authenticated peer delivery outcome is unknown; the message will not be retried"), { code: "DELIVERY_UNKNOWN", messageId: envelope.message_id, cause: error });
      }
      return { status: "DISPATCH_CONFIRMED", message_id: envelope.message_id, requested_capability: requestedCapability, expires_at: envelope.expires_at };
    } catch (error) { if (error.messageId) throw error; throw authError(error.code ?? "UNVERIFIED", error.message); }
  }

  #readVerifiedRow(messageId) {
    const row = this.store.get(messageId);
    if (!row) throw authError("UNVERIFIED", "Unknown peer message id");
    let envelope;
    try {
      envelope = validatePeerEnvelope(JSON.parse(row.envelopeJson));
      const canonical = canonicalPeerEnvelope(envelope);
      if (canonical !== row.envelopeJson || crypto.createHash("sha256").update(canonical).digest("hex") !== row.envelopeSha256) throw new Error("Stored envelope hash mismatch");
    } catch { throw authError("MALFORMED", "Stored peer envelope is malformed"); }
    let peer;
    try { peer = this.keyStore.publicIdentity(envelope.sender.agent); }
    catch { throw authError("UNKNOWN_SIGNER", "Peer signer is not pinned"); }
    const recipientPeer = this.keyStore.publicIdentity(envelope.recipient.agent);
    if (peer.keyId !== envelope.signer_key_id || row.signerKeyId !== envelope.signer_key_id || row.recipientKeyId !== recipientPeer.keyId) throw authError("UNKNOWN_SIGNER", "Peer signer or recipient is not pinned");
    if (!verifyPeerEnvelopeSignature(envelope, row.signature, peer.publicKey)) throw authError("INVALID_SIGNATURE", "Peer signature is invalid");
    return { row, envelope };
  }

  async verifyPeerMessage({ messageId, recipient, revalidateRecipient, resolveSender }) {
    try {
      const { envelope } = this.#readVerifiedRow(messageId);
      if (envelope.kind !== "request") throw authError("INVALID_PARENT", "Only peer requests can be verified with this tool");
      await this.#stable(recipient, revalidateRecipient);
      const mismatch = exactIdentity(scoped(envelope.recipient, envelope), recipient, { includeTurn: false });
      if (mismatch) throw authError(identityCode(mismatch), "Current native receiver does not match the signed recipient");
      if (typeof resolveSender !== "function") throw authError("UNVERIFIED", "Native peer sender lookup is unavailable");
      const sender = this.#assertIdentity(await resolveSender(envelope.sender, envelope), envelope.sender.agent);
      const senderMismatch = exactIdentity(scoped(envelope.sender, envelope), sender);
      if (senderMismatch) throw authError(identityCode(senderMismatch), "Current native sender does not match the signed sender");
      const now = this.now();
      if (now > envelope.expires_at || envelope.issued_at > now + CLOCK_SKEW_MS) throw authError("EXPIRED", "Peer request is expired or from the future");
      if (!rootsPermit(envelope.allowed_roots, recipient) || !rootsPermit(envelope.allowed_roots, sender)) throw authError("WRONG_CWD", "Signed roots exceed the current native endpoints");
      const grant = this.#grant(recipient);
      const senderGrant = this.#grant(sender);
      if (!capabilityAllows(grant.capability_ceiling, envelope.requested_capability) || !capabilityAllows(senderGrant.capability_ceiling, envelope.requested_capability)) throw authError("CAPABILITY_DENIED", "Peer capability exceeds a current endpoint grant");
      if (envelope.parent_message_id) {
        const parentEnvelope = this.#assertVerifiedParentChain(envelope.parent_message_id, now);
        const childSenderMismatch = exactIdentity(scoped(envelope.sender, envelope), scoped(parentEnvelope.recipient, parentEnvelope), { includeTurn: false });
        const childRecipientMismatch = exactIdentity(scoped(envelope.recipient, envelope), scoped(parentEnvelope.sender, parentEnvelope), { includeTurn: false });
        if (childSenderMismatch || childRecipientMismatch) throw authError("INVALID_PARENT", "Peer child does not reverse its immediate parent route");
        if (!capabilityAllows(parentEnvelope.requested_capability, envelope.requested_capability) || envelope.originating_user_task_id !== parentEnvelope.originating_user_task_id || JSON.stringify(envelope.scope) !== JSON.stringify(parentEnvelope.scope) || JSON.stringify(envelope.allowed_roots) !== JSON.stringify(parentEnvelope.allowed_roots)) throw authError("CAPABILITY_DENIED", "Peer child exceeds or changes its parent authority");
      }
      const consumed = this.store.consume(messageId);
      if (consumed.status !== "VERIFIED") throw authError(consumed.status, "Peer request was already consumed or is not dispatch-eligible");
      await this.#stable(recipient, revalidateRecipient);
      this.store.setTurnContext(recipient, messageId, envelope.requested_capability, envelope.expires_at);
      return { status: "VERIFIED", ...envelope };
    } catch (error) {
      if (this.store.get(messageId) && new Set(["INVALID_SIGNATURE", "UNKNOWN_SIGNER", "EXPIRED", "NONCE_REUSE", "INVALID_PARENT", "CAPABILITY_DENIED", "MALFORMED"]).has(error.code)) this.store.reject(messageId, error.code);
      return publicFailure(messageId, error.code);
    }
  }

  async replyToPeerMessage({ parentMessageId, text, sender, revalidateSender, resolveRecipient }) {
    if (sender?.agent !== this.agent) throw authError("WRONG_TASK", "The current MCP side cannot sign for another peer agent");
    if (!this.store.get(parentMessageId)) throw authError("INVALID_PARENT", "Peer reply parent does not exist");
    const verifiedParent = this.#readVerifiedRow(parentMessageId);
    const parent = verifiedParent.row;
    const parentEnvelope = verifiedParent.envelope;
    if (parent.kind !== "request" || parent.state !== "consumed") throw authError("INVALID_PARENT", "Peer reply parent is not a consumed request");
    await this.#stable(sender, revalidateSender);
    const mismatch = exactIdentity(scoped(parentEnvelope.recipient, parentEnvelope), sender, { includeTurn: false });
    if (mismatch) throw authError(identityCode(mismatch), "Current native sender does not own this peer reply");
    const senderGrant = this.#grant(sender);
    if (!capabilityAllows(senderGrant.capability_ceiling, parentEnvelope.requested_capability) || !rootsPermit(parentEnvelope.allowed_roots, sender)) throw authError("CAPABILITY_DENIED", "Current receiver grant no longer permits this peer reply");
    const recipient = { ...scoped(parentEnvelope.sender, parentEnvelope), allowed_roots: parentEnvelope.allowed_roots };
    if (typeof resolveRecipient !== "function") throw authError("UNVERIFIED", "Native reply-recipient lookup is unavailable");
    const liveRecipient = this.#assertIdentity(await resolveRecipient(parentEnvelope.sender, parentEnvelope), parentEnvelope.sender.agent);
    const recipientMismatch = exactIdentity(recipient, liveRecipient, { includeTurn: false });
    const recipientGrant = this.#grant(liveRecipient);
    if (recipientMismatch || !rootsPermit(parentEnvelope.allowed_roots, liveRecipient) || !capabilityAllows(recipientGrant.capability_ceiling, parentEnvelope.requested_capability)) throw authError(recipientMismatch ? identityCode(recipientMismatch) : "CAPABILITY_DENIED", "Current reply recipient no longer matches the parent authority");
    const envelope = this.#envelope({ kind: "reply", text, sender, recipient, capability: parentEnvelope.requested_capability,
      parentMessageId, originTaskId: parentEnvelope.originating_user_task_id, scope: parentEnvelope.scope, allowedRoots: parentEnvelope.allowed_roots });
    const signed = this.#signed(envelope);
    this.store.claimReply(parentMessageId, { ...signed, envelope, recipientKeyId: this.keyStore.publicIdentity(recipient.agent).keyId, direction: `${sender.agent}_to_${recipient.agent}` });
    await this.#stable(sender, revalidateSender);
    this.store.markAttempt(envelope.message_id);
    this.store.markConfirmed(envelope.message_id);
    return { status: "REPLY_SIGNED", message_id: envelope.message_id, parent_message_id: parentMessageId, requested_capability: envelope.requested_capability, expires_at: envelope.expires_at };
  }

  async readPeerReply({ messageId, origin, revalidateOrigin, resolveReplySender }) {
    try {
      const verifiedRequest = this.#readVerifiedRow(messageId);
      const request = verifiedRequest.row;
      const requestEnvelope = verifiedRequest.envelope;
      if (request.kind !== "request") throw authError("INVALID_PARENT", "Original peer request is unavailable");
      await this.#stable(origin, revalidateOrigin);
      const originMismatch = exactIdentity(scoped(requestEnvelope.sender, requestEnvelope), origin, { includeTurn: false });
      if (originMismatch) throw authError(identityCode(originMismatch), "Current native origin does not own this peer request");
      const reply = this.store.replyFor(messageId);
      if (!reply) return { status: request.state === "delivery_unknown" ? "DELIVERY_UNKNOWN" : "PENDING", message_id: messageId };
      const { envelope } = this.#readVerifiedRow(reply.messageId);
      const senderRouteMismatch = exactIdentity(scoped(envelope.sender, envelope), scoped(requestEnvelope.recipient, requestEnvelope), { includeTurn: false });
      const recipientRouteMismatch = exactIdentity(scoped(envelope.recipient, envelope), scoped(requestEnvelope.sender, requestEnvelope), { includeTurn: false });
      if (envelope.kind !== "reply" || envelope.parent_message_id !== messageId || senderRouteMismatch || recipientRouteMismatch ||
          envelope.requested_capability !== requestEnvelope.requested_capability || envelope.originating_user_task_id !== requestEnvelope.originating_user_task_id ||
          JSON.stringify(envelope.scope) !== JSON.stringify(requestEnvelope.scope) || JSON.stringify(envelope.allowed_roots) !== JSON.stringify(requestEnvelope.allowed_roots)) {
        throw authError("INVALID_PARENT", "Peer reply route or parent is invalid");
      }
      if (typeof resolveReplySender !== "function") throw authError("UNVERIFIED", "Native reply-sender lookup is unavailable");
      const liveReplySender = this.#assertIdentity(await resolveReplySender(envelope.sender, envelope), envelope.sender.agent);
      const liveMismatch = exactIdentity(scoped(envelope.sender, envelope), liveReplySender, { includeTurn: false });
      if (liveMismatch) throw authError(identityCode(liveMismatch), "Current native reply sender no longer matches the signed peer");
      const originGrant = this.#grant(origin);
      const replySenderGrant = this.#grant(liveReplySender);
      if (!rootsPermit(envelope.allowed_roots, origin) || !rootsPermit(envelope.allowed_roots, liveReplySender) ||
          !capabilityAllows(originGrant.capability_ceiling, envelope.requested_capability) || !capabilityAllows(replySenderGrant.capability_ceiling, envelope.requested_capability)) {
        throw authError("CAPABILITY_DENIED", "Current endpoint grants no longer permit this peer reply");
      }
      const now = this.now();
      if (now > envelope.expires_at) throw authError("EXPIRED", "Peer reply expired");
      if (reply.state !== "consumed") {
        const consumed = this.store.consume(reply.messageId);
        if (consumed.status !== "VERIFIED") throw authError(consumed.status, "Peer reply cannot be consumed");
      }
      await this.#stable(origin, revalidateOrigin);
      return { status: "VERIFIED", ...envelope };
    } catch (error) { return publicFailure(messageId, error.code); }
  }
}
