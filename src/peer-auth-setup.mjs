#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertAccountIdentity, readBridgeAccounts, requireBridgeAccounts } from "./bridge-account-context.mjs";
import { readClaudeDesktopContext } from "./claude-desktop-context.mjs";
import { assertClaudeSessionProcess, listClaudeSessions } from "./peer-protocol.mjs";
import { PeerAuthKeyStore } from "./peer-auth-keystore-win32.mjs";
import { PeerAuthStore } from "./peer-auth-store.mjs";
import { capturePeerCwd } from "./peer-auth-runtime.mjs";
import { NativeDesktopRelay } from "./native-relay.mjs";
import { matchDesktopProject } from "./thread-delivery.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_ID = /^(?:local_)?[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (!name?.startsWith("--") || argv[index + 1] === undefined) throw new Error("Setup arguments must be explicit --name value pairs");
    if (Object.hasOwn(result, name.slice(2))) throw new Error(`Duplicate setup argument ${name}`);
    result[name.slice(2)] = argv[index + 1];
  }
  return result;
}

function publicStatus(keyStore) {
  const identities = keyStore.publicIdentities();
  return { enabled: true, public_key_ids: Object.fromEntries(Object.entries(identities).map(([agent, identity]) => [agent, identity.keyId])) };
}

export async function inspectCodexTask({ codexTaskId, projectId, canonicalCwd, accountIdentity, relay = new NativeDesktopRelay(), assertAccounts = assertAccountIdentity }) {
  const beforeSend = () => assertAccounts(accountIdentity);
  const projects = (await relay.requestDesktop("list_projects", {}, { accountContext: accountIdentity, beforeSend })).result;
  const project = matchDesktopProject(projects?.projects ?? [], canonicalCwd);
  if (project.projectId !== projectId) throw new Error("The exact saved Codex project does not match setup inputs");
  const response = (await relay.requestDesktop("read_thread", { threadId: codexTaskId, hostId: "local", turnLimit: 1 }, { accountContext: accountIdentity, beforeSend })).result;
  const listing = (await relay.requestDesktop("list_threads", { limit: 50 }, { accountContext: accountIdentity, beforeSend })).result;
  const listed = [...(listing?.pinnedThreads ?? []), ...(listing?.threads ?? [])].filter((thread) => thread.id === codexTaskId && thread.hostId === "local");
  if (response?.thread?.id !== codexTaskId || response.thread.hostId !== "local" || fs.realpathSync.native(response.thread.cwd) !== canonicalCwd || listed.length !== 1 || listed[0].projectId !== projectId || fs.realpathSync.native(listed[0].cwd) !== canonicalCwd) throw new Error("The native Codex task/project/cwd does not match setup inputs");
}

export async function provisionPeerAuth({ root, cwd, projectId, claudeTaskId, claudeSessionId, codexTaskId, capability = "review_only", accounts = readBridgeAccounts(), sessions = listClaudeSessions(), inspectCodex = inspectCodexTask } = {}) {
  if (!path.isAbsolute(root ?? "") || !path.isAbsolute(cwd ?? "") || !UUID.test(projectId ?? "") || !TASK_ID.test(claudeTaskId ?? "") || !claudeSessionId || !UUID.test(codexTaskId ?? "")) throw new Error("Setup requires absolute root/cwd and exact project, Claude task/session, and Codex task identities");
  if (!["read_only", "review_only"].includes(capability)) throw new Error("Initial setup permits only read_only or review_only grants");
  const accountIdentity = requireBridgeAccounts(accounts);
  const matches = sessions.filter((session) => session.alive && session.entrypoint === "claude-desktop" && session.sessionId === claudeSessionId);
  if (matches.length !== 1) throw new Error("Exact Claude Desktop session is missing or ambiguous");
  const session = matches[0];
  assertClaudeSessionProcess(session);
  const desktop = readClaudeDesktopContext(session, { account: accounts.claude });
  const { canonicalCwd, cwdIdentity } = capturePeerCwd(cwd);
  if (desktop.status !== "matched" || desktop.taskId !== claudeTaskId || fs.realpathSync.native(desktop.cwd) !== canonicalCwd) throw new Error("Claude Desktop task, account, or cwd does not match setup inputs");
  if (typeof inspectCodex !== "function") throw new Error("Native Codex task inspection is required before setup");
  await inspectCodex({ codexTaskId, projectId, canonicalCwd, accountIdentity });
  const keyStore = new PeerAuthKeyStore({ root });
  const created = keyStore.setup();
  const store = new PeerAuthStore({ root, validateStorage: (paths) => keyStore.validatePaths(Array.isArray(paths) ? paths : [paths]), protectStorage: (paths) => keyStore.protectPaths(Array.isArray(paths) ? paths : [paths]) });
  try {
    store.provisionGrant({ agent: "claude", accountFingerprint: accountIdentity.claude, taskId: claudeTaskId, sessionId: claudeSessionId, cwd: canonicalCwd, cwdIdentity, projectId, capabilityCeiling: capability });
    store.provisionGrant({ agent: "codex", accountFingerprint: accountIdentity.codex, taskId: codexTaskId, sessionId: "", cwd: canonicalCwd, cwdIdentity, projectId, capabilityCeiling: capability });
    return { ...created, ...publicStatus(keyStore), ready: true, capability_ceiling: capability, task_bindings: { claude: claudeTaskId, codex: codexTaskId }, project_id: projectId };
  } finally { store.close(); }
}

export function peerAuthSetupStatus(root) {
  const keyStore = new PeerAuthKeyStore({ root });
  keyStore.validate();
  const database = path.join(root, "state.sqlite3");
  if (!fs.existsSync(database)) return { ...publicStatus(keyStore), ready: false };
  const store = new PeerAuthStore({ root, validateStorage: (paths) => keyStore.validatePaths(Array.isArray(paths) ? paths : [paths]), protectStorage: (paths) => keyStore.protectPaths(Array.isArray(paths) ? paths : [paths]) });
  try { return { ...publicStatus(keyStore), ready: store.readyGrants() }; } finally { store.close(); }
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    const values = args(process.argv.slice(2));
    const output = values.status === "1" ? peerAuthSetupStatus(values.root) : await provisionPeerAuth({
      root: values.root, cwd: values.cwd, projectId: values["project-id"], claudeTaskId: values["claude-task"], claudeSessionId: values["claude-session"], codexTaskId: values["codex-task"], capability: values.capability,
    });
    process.stdout.write(`${JSON.stringify(output)}\n`);
  } catch (error) {
    process.stderr.write(`Peer authentication setup failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
