import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const ELIGIBLE_CONSUME = new Set(["dispatch_attempted", "dispatch_confirmed", "delivery_unknown"]);
const MAX_ROWS = 100000;

function safeDatabasePath(root, file) {
  if (!path.isAbsolute(root) || path.dirname(file) !== root) throw new Error("Peer authentication database path is invalid");
  const rootStatus = fs.lstatSync(root);
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) throw new Error("Peer authentication root is not a regular directory");
  if (fs.existsSync(file)) {
    const status = fs.lstatSync(file);
    if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) throw new Error("Peer authentication database is not a safe regular file");
  }
}

function rowToMessage(row) {
  if (!row) return null;
  return {
    messageId: row.message_id, nonce: row.nonce, signerKeyId: row.signer_key_id, recipientKeyId: row.recipient_key_id,
    kind: row.kind, direction: row.direction, envelopeJson: row.envelope_json, envelopeSha256: row.envelope_sha256,
    signature: row.signature, state: row.state, createdAt: row.created_at, expiresAt: row.expires_at,
    parentMessageId: row.parent_message_id, originatingUserTaskId: row.originating_user_task_id,
    dispatchAttemptedAt: row.dispatch_attempted_at, dispatchOutcome: row.dispatch_outcome,
    consumedAt: row.consumed_at, repliedByMessageId: row.replied_by_message_id, rejectionReason: row.rejection_reason,
  };
}

export class PeerAuthStore {
  constructor({ root, validateStorage = () => {}, protectStorage = () => {}, maxRows = MAX_ROWS, now = Date.now } = {}) {
    if (typeof root !== "string" || !path.isAbsolute(root)) throw new Error("Peer authentication store requires an absolute root");
    this.root = path.resolve(root); this.file = path.join(this.root, "state.sqlite3"); this.validateStorage = validateStorage; this.protectStorage = protectStorage; this.maxRows = maxRows; this.now = now;
    if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > MAX_ROWS) throw new Error("Peer message row bound is invalid");
    safeDatabasePath(this.root, this.file); this.validateStorage([this.root]);
    const artifacts = [this.file, `${this.file}-wal`, `${this.file}-shm`];
    const existing = new Map();
    const existingPaths = [];
    for (const candidate of artifacts) {
      if (!fs.existsSync(candidate)) continue;
      const status = fs.lstatSync(candidate);
      if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) throw new Error("Peer authentication SQLite artifact is unsafe");
      existingPaths.push(candidate);
      existing.set(candidate, { dev: status.dev, ino: status.ino });
    }
    if (existingPaths.length) this.validateStorage(existingPaths);
    this.db = new DatabaseSync(this.file, { timeout: 5000 });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY, nonce TEXT NOT NULL, signer_key_id TEXT NOT NULL, recipient_key_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('request','reply')), direction TEXT NOT NULL, envelope_json TEXT NOT NULL,
        envelope_sha256 TEXT NOT NULL, signature TEXT NOT NULL, state TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, parent_message_id TEXT,
        originating_user_task_id TEXT NOT NULL, dispatch_attempted_at INTEGER, dispatch_outcome TEXT,
        consumed_at INTEGER, replied_by_message_id TEXT, rejection_reason TEXT,
        UNIQUE(signer_key_id, nonce), FOREIGN KEY(parent_message_id) REFERENCES messages(message_id)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS one_reply_per_parent ON messages(parent_message_id) WHERE kind='reply';
      CREATE TABLE IF NOT EXISTS turn_context (
        receiver_agent TEXT NOT NULL, receiver_task_id TEXT NOT NULL, receiver_session_id TEXT NOT NULL,
        receiver_turn_id TEXT NOT NULL, message_id TEXT NOT NULL, capability TEXT NOT NULL, expires_at INTEGER NOT NULL,
        PRIMARY KEY(receiver_agent, receiver_task_id, receiver_session_id, receiver_turn_id),
        FOREIGN KEY(message_id) REFERENCES messages(message_id)
      );
      CREATE TABLE IF NOT EXISTS grants (
        agent TEXT NOT NULL, account_fingerprint TEXT NOT NULL, task_id TEXT NOT NULL, session_id TEXT NOT NULL,
        cwd TEXT NOT NULL, cwd_identity TEXT NOT NULL, project_id TEXT NOT NULL, capability_ceiling TEXT NOT NULL,
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), PRIMARY KEY(agent, account_fingerprint, task_id, cwd, project_id)
      );
    `);
    this.paths = new Map();
    this.#captureArtifacts(existing);
  }

  close() { this.db.close(); }
  #transaction(callback) {
    this.db.exec("BEGIN IMMEDIATE");
    try { const value = callback(); this.db.exec("COMMIT"); return value; }
    catch (error) { try { this.db.exec("ROLLBACK"); } catch {} throw error; }
  }
  #captureArtifacts(existing) {
    for (const candidate of [this.file, `${this.file}-wal`, `${this.file}-shm`]) {
      if (!fs.existsSync(candidate)) continue;
      const status = fs.lstatSync(candidate);
      if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) throw new Error("Peer authentication SQLite artifact is unsafe");
      const prior = existing.get(candidate);
      if (prior && (prior.dev !== status.dev || prior.ino !== status.ino)) throw new Error("Peer authentication SQLite artifact was replaced during open");
      if (!prior) this.protectStorage([candidate]);
      this.validateStorage([candidate]);
      this.paths.set(candidate, { dev: status.dev, ino: status.ino });
    }
  }
  #check() {
    safeDatabasePath(this.root, this.file);
    const validate = [this.root];
    for (const candidate of [this.file, `${this.file}-wal`, `${this.file}-shm`]) {
      if (!fs.existsSync(candidate)) { if (this.paths.has(candidate)) throw new Error("Peer authentication SQLite artifact disappeared"); continue; }
      const status = fs.lstatSync(candidate);
      if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) throw new Error("Peer authentication SQLite artifact is unsafe");
      const expected = this.paths.get(candidate);
      if (expected && (expected.dev !== status.dev || expected.ino !== status.ino)) throw new Error("Peer authentication SQLite artifact was replaced");
      if (!expected) throw new Error("Peer authentication SQLite artifact appeared outside initialization");
      validate.push(candidate);
    }
    this.validateStorage(validate);
  }

  provisionGrant(grant) {
    this.#check();
    this.db.prepare(`INSERT INTO grants(agent,account_fingerprint,task_id,session_id,cwd,cwd_identity,project_id,capability_ceiling,enabled)
      VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(agent,account_fingerprint,task_id,cwd,project_id) DO UPDATE SET
      session_id=excluded.session_id,cwd_identity=excluded.cwd_identity,capability_ceiling=excluded.capability_ceiling,enabled=1`).run(
      grant.agent, grant.accountFingerprint, grant.taskId, grant.sessionId ?? "", grant.cwd, grant.cwdIdentity, grant.projectId, grant.capabilityCeiling,
    );
  }

  grantFor(identity) {
    this.#check();
    return this.db.prepare(`SELECT * FROM grants WHERE agent=? AND account_fingerprint=? AND task_id=? AND cwd=? AND project_id=? AND enabled=1`).get(
      identity.agent, identity.account_fingerprint, identity.task_id, identity.canonical_cwd, identity.project_id,
    ) ?? null;
  }

  resolveGrant({ agent, accountFingerprint, taskId, sessionId, cwd }) {
    this.#check();
    const rows = this.db.prepare(`SELECT * FROM grants WHERE agent=? AND account_fingerprint=? AND task_id=? AND session_id=? AND cwd=? AND enabled=1`).all(
      agent, accountFingerprint, taskId, sessionId ?? "", cwd,
    );
    if (rows.length !== 1) throw Object.assign(new Error(rows.length ? "Multiple peer grants match the native task" : "No peer grant matches the native task"), { code: "CAPABILITY_DENIED" });
    return rows[0];
  }

  issue({ envelopeJson, envelopeSha256, envelope, signature, recipientKeyId, direction }) {
    this.#check();
    return this.#transaction(() => {
      const count = Number(this.db.prepare("SELECT COUNT(*) count FROM messages").get().count);
      if (count >= this.maxRows) throw Object.assign(new Error("Peer message store reached its bounded capacity"), { code: "STORE_CAPACITY" });
      this.db.prepare(`INSERT INTO messages(message_id,nonce,signer_key_id,recipient_key_id,kind,direction,envelope_json,envelope_sha256,signature,state,created_at,expires_at,parent_message_id,originating_user_task_id)
        VALUES(?,?,?,?,?,?,?,?,?,'issued',?,?,?,?)`).run(
        envelope.message_id, envelope.nonce, envelope.signer_key_id, recipientKeyId, envelope.kind, direction,
        envelopeJson, envelopeSha256, signature, envelope.issued_at, envelope.expires_at,
        envelope.parent_message_id, envelope.originating_user_task_id,
      );
      return this.get(envelope.message_id);
    });
  }

  get(messageId) {
    this.#check();
    return rowToMessage(this.db.prepare("SELECT * FROM messages WHERE message_id=?").get(messageId));
  }

  markAttempt(messageId) {
    this.#check();
    const at = this.now();
    const changed = this.db.prepare("UPDATE messages SET state='dispatch_attempted',dispatch_attempted_at=?,dispatch_outcome='attempted' WHERE message_id=? AND state='issued'").run(at, messageId).changes;
    if (changed !== 1) throw Object.assign(new Error("Peer message already has a dispatch attempt"), { code: "ALREADY_ATTEMPTED" });
    return this.get(messageId);
  }

  markConfirmed(messageId) {
    this.#check();
    this.db.prepare("UPDATE messages SET state='dispatch_confirmed',dispatch_outcome='confirmed' WHERE message_id=? AND state='dispatch_attempted'").run(messageId);
    return this.get(messageId);
  }

  markDeliveryUnknown(messageId) {
    this.#check();
    this.db.prepare("UPDATE messages SET state='delivery_unknown',dispatch_outcome='unknown' WHERE message_id=? AND state='dispatch_attempted'").run(messageId);
    return this.get(messageId);
  }

  reject(messageId, reason) {
    this.#check();
    this.db.prepare("UPDATE messages SET state='rejected',rejection_reason=? WHERE message_id=? AND state NOT IN ('consumed','replied')").run(reason, messageId);
    return this.get(messageId);
  }

  consume(messageId) {
    this.#check();
    return this.#transaction(() => {
      const row = this.get(messageId);
      if (!row) return { status: "UNVERIFIED", row: null };
      if (["consumed", "replied"].includes(row.state)) return { status: "REPLAY", row };
      if (row.state === "rejected") return { status: row.rejectionReason ?? "UNVERIFIED", row };
      if (!ELIGIBLE_CONSUME.has(row.state)) return { status: "UNVERIFIED", row };
      const changed = this.db.prepare("UPDATE messages SET state='consumed',consumed_at=? WHERE message_id=? AND state IN ('dispatch_attempted','dispatch_confirmed','delivery_unknown')").run(this.now(), messageId).changes;
      return changed === 1 ? { status: "VERIFIED", row: this.get(messageId) } : { status: "REPLAY", row: this.get(messageId) };
    });
  }

  claimReply(parentMessageId, values) {
    this.#check();
    return this.#transaction(() => {
      const parent = this.get(parentMessageId);
      if (!parent || parent.kind !== "request" || parent.state !== "consumed" || parent.repliedByMessageId) throw Object.assign(new Error("Peer reply parent is missing, unconsumed, or already replied"), { code: "INVALID_PARENT" });
      const count = Number(this.db.prepare("SELECT COUNT(*) count FROM messages").get().count);
      if (count >= this.maxRows) throw Object.assign(new Error("Peer message store reached its bounded capacity"), { code: "STORE_CAPACITY" });
      const { envelope, envelopeJson, envelopeSha256, signature, recipientKeyId, direction } = values;
      if (envelope.parent_message_id !== parentMessageId) throw Object.assign(new Error("Peer reply parent mismatch"), { code: "INVALID_PARENT" });
      this.db.prepare(`INSERT INTO messages(message_id,nonce,signer_key_id,recipient_key_id,kind,direction,envelope_json,envelope_sha256,signature,state,created_at,expires_at,parent_message_id,originating_user_task_id)
        VALUES(?,?,?,?,?,?,?,?,?,'issued',?,?,?,?)`).run(
        envelope.message_id, envelope.nonce, envelope.signer_key_id, recipientKeyId, envelope.kind, direction,
        envelopeJson, envelopeSha256, signature, envelope.issued_at, envelope.expires_at,
        envelope.parent_message_id, envelope.originating_user_task_id,
      );
      const changed = this.db.prepare("UPDATE messages SET state='replied',replied_by_message_id=? WHERE message_id=? AND state='consumed' AND replied_by_message_id IS NULL").run(envelope.message_id, parentMessageId).changes;
      if (changed !== 1) throw Object.assign(new Error("Peer reply parent was already claimed"), { code: "INVALID_PARENT" });
      return { parent, reply: this.get(envelope.message_id) };
    });
  }

  setTurnContext(identity, messageId, capability, expiresAt) {
    this.#check();
    if (!identity.turn_id) return;
    this.db.prepare(`INSERT OR IGNORE INTO turn_context(receiver_agent,receiver_task_id,receiver_session_id,receiver_turn_id,message_id,capability,expires_at)
      VALUES(?,?,?,?,?,?,?)`).run(
      identity.agent, identity.task_id, identity.session_id ?? "", identity.turn_id, messageId, capability, expiresAt,
    );
    const bound = this.db.prepare("SELECT message_id,capability,expires_at FROM turn_context WHERE receiver_agent=? AND receiver_task_id=? AND receiver_session_id=? AND receiver_turn_id=?").get(identity.agent, identity.task_id, identity.session_id ?? "", identity.turn_id);
    if (bound.message_id !== messageId || bound.capability !== capability || bound.expires_at !== expiresAt) throw Object.assign(new Error("Native turn already has a different peer parent context"), { code: "INVALID_PARENT" });
  }

  contextsFor(identity) {
    this.#check();
    if (!identity.turn_id) return [];
    return this.db.prepare(`SELECT * FROM turn_context WHERE receiver_agent=? AND receiver_task_id=? AND receiver_session_id=? AND receiver_turn_id=?`).all(
      identity.agent, identity.task_id, identity.session_id ?? "", identity.turn_id,
    );
  }

  replyFor(parentMessageId) {
    this.#check();
    return rowToMessage(this.db.prepare("SELECT * FROM messages WHERE kind='reply' AND parent_message_id=?").get(parentMessageId));
  }

  count() { return Number(this.db.prepare("SELECT COUNT(*) count FROM messages").get().count); }
  readyGrants() {
    this.#check();
    const rows = this.db.prepare("SELECT agent,COUNT(*) count FROM grants WHERE enabled=1 GROUP BY agent").all();
    const agents = new Map(rows.map((row) => [row.agent, Number(row.count)]));
    return agents.has("claude") && agents.has("codex");
  }
}
