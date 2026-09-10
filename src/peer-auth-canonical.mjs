import crypto from "node:crypto";

export const PEER_AUTH_PROTOCOL = "codex-claude-peer-auth/1";
export const PEER_AUTH_DOMAIN = Buffer.from(`${PEER_AUTH_PROTOCOL}\0`, "utf8");
export const PEER_CAPABILITIES = Object.freeze({
  read_only: Object.freeze(["read_project"]),
  review_only: Object.freeze(["read_project", "review_project"]),
  edit_project: Object.freeze(["read_project", "review_project", "edit_project"]),
  run_tests: Object.freeze(["read_project", "run_declared_tests"]),
});

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const TOP_KEYS = ["protocol", "kind", "message_id", "parent_message_id", "nonce", "issued_at", "expires_at", "sender", "recipient", "scope", "originating_user_task_id", "requested_capability", "allowed_roots", "payload", "signer_key_id"];
const ENDPOINT_KEYS = ["agent", "account_fingerprint", "task_id", "session_id", "turn_id"];
const RECIPIENT_KEYS = ["agent", "account_fingerprint", "task_id", "session_id"];
const SCOPE_KEYS = ["canonical_cwd", "cwd_identity", "project_id", "project_host_id"];
const PAYLOAD_KEYS = ["media_type", "text", "sha256"];

function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function exactKeys(value, keys, label) {
  if (!object(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new Error(`${label} has an invalid schema`);
}
function nfc(value, label, { empty = false } = {}) {
  if (typeof value !== "string" || (!empty && !value.length) || value !== value.normalize("NFC") || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) throw new Error(`${label} must be canonical NFC text`);
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error(`${label} contains an unpaired Unicode surrogate`);
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error(`${label} contains an unpaired Unicode surrogate`);
  }
  return value;
}
function safeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer`);
}

export function jcsCanonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("Canonical peer envelopes allow safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcsCanonicalize).join(",")}]`;
  if (!object(value)) throw new Error("Unsupported canonical peer-envelope value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcsCanonicalize(value[key])}`).join(",")}}`;
}

export function normalizePeerText(text) {
  return nfc(text, "payload.text", { empty: true });
}

export function peerPayloadHash(text) {
  return crypto.createHash("sha256").update(normalizePeerText(text), "utf8").digest("hex");
}

export function peerPublicKeyId(spki) {
  return crypto.createHash("sha256").update(spki).digest("hex");
}

export function capabilityAllows(ceiling, requested) {
  if (!Object.hasOwn(PEER_CAPABILITIES, ceiling) || !Object.hasOwn(PEER_CAPABILITIES, requested)) return false;
  const allowed = PEER_CAPABILITIES[ceiling];
  const wanted = PEER_CAPABILITIES[requested];
  return Boolean(allowed && wanted && wanted.every((action) => allowed.includes(action)));
}

function validateEndpoint(endpoint, keys, label) {
  exactKeys(endpoint, keys, label);
  if (!new Set(["claude", "codex"]).has(endpoint.agent)) throw new Error(`${label}.agent is invalid`);
  for (const key of keys.filter((key) => key !== "agent")) {
    if (endpoint[key] !== null) nfc(endpoint[key], `${label}.${key}`);
  }
  if (!endpoint.account_fingerprint || !endpoint.task_id) throw new Error(`${label} lacks a required identity`);
}

export function validatePeerEnvelope(envelope) {
  exactKeys(envelope, TOP_KEYS, "peer envelope");
  if (envelope.protocol !== PEER_AUTH_PROTOCOL || !new Set(["request", "reply"]).has(envelope.kind)) throw new Error("Peer protocol or kind is invalid");
  if (!UUID_V4.test(envelope.message_id)) throw new Error("Peer message id or nonce is invalid");
  const nonce = typeof envelope.nonce === "string" ? Buffer.from(envelope.nonce, "base64url") : Buffer.alloc(0);
  if (nonce.length !== 32 || nonce.toString("base64url") !== envelope.nonce) throw new Error("Peer message id or nonce is invalid");
  if (envelope.parent_message_id !== null && !UUID_V4.test(envelope.parent_message_id)) throw new Error("Peer parent id is invalid");
  if (envelope.kind === "reply" && envelope.parent_message_id === null) throw new Error("A peer reply requires a parent");
  safeInteger(envelope.issued_at, "issued_at");
  safeInteger(envelope.expires_at, "expires_at");
  if (envelope.expires_at <= envelope.issued_at || envelope.expires_at - envelope.issued_at > 900000) throw new Error("Peer expiry is invalid");
  validateEndpoint(envelope.sender, ENDPOINT_KEYS, "sender");
  validateEndpoint(envelope.recipient, RECIPIENT_KEYS, "recipient");
  if (envelope.sender.agent === envelope.recipient.agent) throw new Error("Peer endpoints must be different agents");
  exactKeys(envelope.scope, SCOPE_KEYS, "scope");
  for (const key of SCOPE_KEYS) nfc(envelope.scope[key], `scope.${key}`);
  if (envelope.scope.project_host_id !== "local") throw new Error("Only a local project is supported");
  nfc(envelope.originating_user_task_id, "originating_user_task_id");
  if (!Object.hasOwn(PEER_CAPABILITIES, envelope.requested_capability)) throw new Error("Peer capability is invalid");
  if (!Array.isArray(envelope.allowed_roots) || !envelope.allowed_roots.length || new Set(envelope.allowed_roots).size !== envelope.allowed_roots.length ||
      envelope.allowed_roots.some((root) => nfc(root, "allowed root") !== root) || [...envelope.allowed_roots].sort().some((root, i) => root !== envelope.allowed_roots[i])) throw new Error("Allowed roots must be sorted unique canonical paths");
  exactKeys(envelope.payload, PAYLOAD_KEYS, "payload");
  if (envelope.payload.media_type !== "text/plain; charset=utf-8") throw new Error("Peer payload media type is invalid");
  nfc(envelope.payload.text, "payload.text", { empty: true });
  if (!SHA256.test(envelope.payload.sha256) || envelope.payload.sha256 !== peerPayloadHash(envelope.payload.text)) throw new Error("Peer payload hash is invalid");
  if (!SHA256.test(envelope.signer_key_id)) throw new Error("Peer signer key id is invalid");
  return envelope;
}

export function canonicalPeerEnvelope(envelope) {
  validatePeerEnvelope(envelope);
  return jcsCanonicalize(envelope);
}

export function peerSignatureInput(envelope) {
  return Buffer.concat([PEER_AUTH_DOMAIN, Buffer.from(canonicalPeerEnvelope(envelope), "utf8")]);
}

export function signPeerEnvelope(envelope, privateKey) {
  return crypto.sign(null, peerSignatureInput(envelope), privateKey).toString("base64url");
}

export function verifyPeerEnvelopeSignature(envelope, signature, publicKey) {
  if (typeof signature !== "string") return false;
  const bytes = Buffer.from(signature, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== signature) return false;
  try { return crypto.verify(null, peerSignatureInput(envelope), publicKey, bytes); }
  catch { return false; }
}

export function buildPeerEnvelope({ kind = "request", messageId = crypto.randomUUID(), parentMessageId = null, nonce = crypto.randomBytes(32).toString("base64url"), issuedAt, expiresAt, sender, recipient, scope, originatingUserTaskId, requestedCapability = "read_only", allowedRoots, text, signerKeyId }) {
  const envelope = {
    protocol: PEER_AUTH_PROTOCOL, kind, message_id: messageId, parent_message_id: parentMessageId, nonce,
    issued_at: issuedAt, expires_at: expiresAt,
    sender: { agent: sender.agent, account_fingerprint: sender.account_fingerprint, task_id: sender.task_id, session_id: sender.session_id ?? null, turn_id: sender.turn_id ?? null },
    recipient: { agent: recipient.agent, account_fingerprint: recipient.account_fingerprint, task_id: recipient.task_id, session_id: recipient.session_id ?? null },
    scope: { canonical_cwd: scope.canonical_cwd, cwd_identity: scope.cwd_identity, project_id: scope.project_id, project_host_id: scope.project_host_id },
    originating_user_task_id: originatingUserTaskId, requested_capability: requestedCapability,
    allowed_roots: [...allowedRoots].sort(),
    payload: { media_type: "text/plain; charset=utf-8", text: normalizePeerText(text), sha256: peerPayloadHash(text) },
    signer_key_id: signerKeyId,
  };
  return validatePeerEnvelope(envelope);
}
