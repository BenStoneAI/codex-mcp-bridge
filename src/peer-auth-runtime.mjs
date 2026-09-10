import fs from "node:fs";
import path from "node:path";
import { PeerAuthKeyStore, peerAuthDirectory, peerAuthEnabled } from "./peer-auth-keystore-win32.mjs";
import { PeerAuthStore } from "./peer-auth-store.mjs";
import { PeerAuthService } from "./peer-auth-service.mjs";

function directoryIdentity(canonicalCwd) {
  const before = fs.lstatSync(canonicalCwd, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) throw new Error("Peer project directory is not a regular directory");
  const resolved = fs.realpathSync.native(canonicalCwd);
  const after = fs.statSync(resolved, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino) throw new Error("Peer project directory identity changed");
  return `${after.dev}:${after.ino}`;
}

export function capturePeerCwd(cwd) {
  if (typeof cwd !== "string" || !path.isAbsolute(cwd)) throw new Error("Peer native cwd must be absolute");
  const canonicalCwd = fs.realpathSync.native(cwd);
  return { canonicalCwd, cwdIdentity: directoryIdentity(canonicalCwd) };
}

export class PeerAuthRuntime {
  constructor({ agent, root, keyStore, store, service } = {}) {
    this.agent = agent;
    this.keyStore = keyStore ?? new PeerAuthKeyStore({ root });
    this.keyStore.validate();
    this.store = store ?? new PeerAuthStore({
      root,
      validateStorage: (paths) => this.keyStore.validatePaths(Array.isArray(paths) ? paths : [paths]),
      protectStorage: (paths) => this.keyStore.protectPaths(Array.isArray(paths) ? paths : [paths]),
    });
    this.service = service ?? new PeerAuthService({ agent, store: this.store, keyStore: this.keyStore });
  }

  identity({ agent, accountFingerprint, taskId, sessionId = null, turnId = null, cwd }) {
    const { canonicalCwd, cwdIdentity } = capturePeerCwd(cwd);
    const grant = this.store.resolveGrant({ agent, accountFingerprint, taskId, sessionId, cwd: canonicalCwd });
    if (grant.cwd_identity !== cwdIdentity) throw Object.assign(new Error("Peer project directory identity changed from its grant"), { code: "WRONG_CWD" });
    return {
      agent, account_fingerprint: accountFingerprint, task_id: taskId, session_id: sessionId, turn_id: turnId,
      canonical_cwd: canonicalCwd, cwd_identity: cwdIdentity, project_id: grant.project_id,
      project_host_id: "local", allowed_roots: [canonicalCwd],
    };
  }

  status() {
    const identities = this.keyStore.publicIdentities();
    return { enabled: true, ready: this.store.readyGrants(), public_key_ids: Object.fromEntries(Object.entries(identities).map(([agent, identity]) => [agent, identity.keyId])) };
  }

  close() { this.store.close(); }
}

export function createPeerAuthRuntime(agent, { env = process.env } = {}) {
  if (!peerAuthEnabled(env)) return null;
  return new PeerAuthRuntime({ agent, root: peerAuthDirectory(env) });
}
