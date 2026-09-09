import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_ROLLOUT_BYTES = 16 * 1024 * 1024;
const MAX_ENTRIES = 100000;
const MAX_DIRECTORIES = 4096;
const MAX_REPLY_BYTES = 1024 * 1024;
const COMPLETED = new Set(["task_complete", "task_completed", "turn_complete", "turn_completed"]);
const STARTED = new Set(["task_started", "turn_started"]);
const FAILED = new Set(["task_aborted", "turn_aborted", "task_failed", "turn_failed"]);

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function unavailable(reason) {
  return { status: "unavailable", reason: reason?.message ?? String(reason) };
}

function configuredSessions(env) {
  const configuredHome = env.CODEX_HOME || path.join(env.HOME || env.USERPROFILE || os.homedir(), ".codex");
  if (!path.isAbsolute(configuredHome)) throw new Error("The configured Codex home must be absolute");
  const homeStatus = fs.lstatSync(configuredHome);
  if (!homeStatus.isDirectory() || homeStatus.isSymbolicLink()) throw new Error("The configured Codex home is not a regular directory");
  const sessions = path.join(configuredHome, "sessions");
  const status = fs.lstatSync(sessions);
  if (!status.isDirectory() || status.isSymbolicLink()) throw new Error("The Codex sessions path is not a regular directory");
  const canonicalHome = fs.realpathSync.native(configuredHome);
  const canonicalSessions = fs.realpathSync.native(sessions);
  const relative = path.relative(canonicalHome, canonicalSessions);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("The Codex sessions path escapes the configured home");
  return canonicalSessions;
}

function findRollout(threadId, env) {
  if (!UUID.test(threadId)) throw new Error("The Codex task identity is invalid");
  const sessions = configuredSessions(env);
  const queue = [{ directory: sessions, depth: 0 }];
  const matches = [];
  let entries = 0;
  let directories = 0;
  while (queue.length) {
    const { directory, depth } = queue.pop();
    if (++directories > MAX_DIRECTORIES) throw new Error("The bounded Codex sessions scan exceeded its directory limit");
    const children = fs.readdirSync(directory, { withFileTypes: true });
    entries += children.length;
    if (entries > MAX_ENTRIES) throw new Error("The bounded Codex sessions scan exceeded its entry limit");
    for (const child of children) {
      const candidate = path.join(directory, child.name);
      if (depth < 3 && (depth === 0 ? /^\d{4}$/ : /^\d{2}$/).test(child.name)) {
        if (child.isSymbolicLink()) throw new Error("The Codex sessions scan encountered a linked date directory");
        if (child.isDirectory()) {
          const resolved = fs.realpathSync.native(candidate);
          const relative = path.relative(sessions, resolved);
          if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("A Codex date directory escapes the sessions path");
          queue.push({ directory: resolved, depth: depth + 1 });
        }
      }
      if (depth === 3 && child.name.startsWith("rollout-") && child.name.endsWith(`-${threadId}.jsonl`)) matches.push(candidate);
    }
  }
  if (matches.length !== 1) throw new Error(matches.length ? "Multiple rollouts match the Codex task" : "No rollout matches the Codex task");
  const status = fs.lstatSync(matches[0]);
  if (!status.isFile() || status.isSymbolicLink()) throw new Error("The Codex rollout is not a regular file");
  return { file: matches[0], sessions };
}

function pathIdentity(candidate, kind) {
  const status = fs.lstatSync(candidate);
  if ((kind === "file" ? !status.isFile() : !status.isDirectory()) || status.isSymbolicLink()) throw new Error(`The Codex rollout ${kind === "file" ? "file" : "ancestor"} is not regular`);
  return { path: candidate, dev: status.dev, ino: status.ino };
}

function capturePathBoundary(file, sessions) {
  const resolvedFile = fs.realpathSync.native(file);
  const relative = path.relative(sessions, resolvedFile);
  if (relative.startsWith("..") || path.isAbsolute(relative) || path.relative(file, resolvedFile)) throw new Error("The Codex rollout path escapes its sessions directory");
  const ancestors = [];
  let current = path.dirname(file);
  for (;;) {
    const resolved = fs.realpathSync.native(current);
    const within = path.relative(sessions, resolved);
    if (within.startsWith("..") || path.isAbsolute(within) || path.relative(current, resolved)) throw new Error("A Codex rollout ancestor redirects outside its sessions directory");
    ancestors.push(pathIdentity(current, "directory"));
    if (!path.relative(sessions, current)) break;
    const parent = path.dirname(current);
    if (parent === current) throw new Error("The Codex rollout path has no sessions ancestor");
    current = parent;
  }
  return { file: pathIdentity(file, "file"), ancestors };
}

function samePathBoundary(expected, current) {
  return expected.file.dev === current.file.dev && expected.file.ino === current.file.ino &&
    expected.ancestors.length === current.ancestors.length && expected.ancestors.every((entry, index) =>
      entry.path === current.ancestors[index].path && entry.dev === current.ancestors[index].dev && entry.ino === current.ancestors[index].ino);
}

function readStable(found, maxBytes) {
  const { file, sessions } = found;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_ROLLOUT_BYTES) throw new Error("The Codex rollout read limit is invalid");
  const beforeBoundary = capturePathBoundary(file, sessions);
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor);
    if (before.dev !== beforeBoundary.file.dev || before.ino !== beforeBoundary.file.ino) throw new Error("The Codex rollout changed while opening");
    if (!before.isFile() || before.size === 0 || before.size > maxBytes) throw new Error("The Codex rollout is empty or exceeds the bounded read limit");
    const data = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(descriptor, data, offset, data.length - offset, offset);
      if (!count) throw new Error("The Codex rollout changed while reading");
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const afterBoundary = capturePathBoundary(file, sessions);
    if (!samePathBoundary(beforeBoundary, afterBoundary) || before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs || before.ino !== after.ino || before.dev !== after.dev ||
        before.ino !== afterBoundary.file.ino || before.dev !== afterBoundary.file.dev) throw new Error("The Codex rollout changed while reading");
    if (data.at(-1) !== 0x0a) throw new Error("The Codex rollout has an incomplete final record");
    return { data, identity: { dev: before.dev, ino: before.ino } };
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseRecords(data) {
  const records = [];
  let offset = 0;
  while (offset < data.length) {
    const newline = data.indexOf(0x0a, offset);
    if (newline < 0) throw new Error("The Codex rollout has an incomplete final record");
    const raw = data.subarray(offset, newline).toString("utf8");
    const start = offset;
    offset = newline + 1;
    if (!raw) continue;
    const record = JSON.parse(raw);
    if (!object(record) || !object(record.payload)) throw new Error("The Codex rollout contains an invalid record");
    records.push({ record, start });
  }
  return records;
}

function canonicalDirectory(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)) throw new Error(`${label} is missing or invalid`);
  const status = fs.lstatSync(value);
  if (!status.isDirectory() || status.isSymbolicLink()) throw new Error(`${label} is not a regular directory`);
  return fs.realpathSync.native(value);
}

function validateSession(records, threadId, expectedCwd) {
  const sessions = records.filter(({ record }) => record.type === "session_meta").map(({ record }) => record.payload);
  if (sessions.length !== 1) throw new Error("The Codex rollout has ambiguous session identity");
  const session = sessions[0];
  if (session.id !== threadId || session.originator !== "Codex Desktop" || session.source !== "vscode") throw new Error("The rollout does not confirm the exact native Codex Desktop task");
  if (canonicalDirectory(session.cwd, "The rollout workspace") !== expectedCwd) throw new Error("The rollout workspace does not match the selected native task");
}

function delegationOutput(executorThreadId, prompt) {
  return `<codex_delegation>\n  <source_thread_id>${executorThreadId}</source_thread_id>\n  <input>${prompt}</input>\n</codex_delegation>`;
}

export function captureCodexRolloutWatermark({ threadId, expectedCwd }, { env = process.env, maxRolloutBytes = MAX_ROLLOUT_BYTES } = {}) {
  try {
    const cwd = canonicalDirectory(expectedCwd, "The selected native task workspace");
    const found = findRollout(threadId, env);
    const snapshot = readStable(found, maxRolloutBytes);
    const records = parseRecords(snapshot.data);
    validateSession(records, threadId, cwd);
    return {
      status: "available",
      threadId,
      cwd,
      file: found.file,
      size: snapshot.data.length,
      prefixSha256: crypto.createHash("sha256").update(snapshot.data).digest("hex"),
      identity: snapshot.identity,
    };
  } catch (error) {
    return unavailable(error);
  }
}

export function readCodexNativeTurnResponse({ threadId, turnId, previousTurnId, expectedCwd, executorThreadId, prompt, watermark }, { env = process.env, maxRolloutBytes = MAX_ROLLOUT_BYTES } = {}) {
  try {
    if (!UUID.test(threadId) || !UUID.test(turnId) || !UUID.test(executorThreadId)) throw new Error("The native response identity is invalid");
    if (turnId === previousTurnId) throw new Error("The observed turn was already present before dispatch");
    if (typeof prompt !== "string" || !prompt.length) throw new Error("The exact dispatched prompt is unavailable");
    if (!object(watermark) || watermark.status !== "available" || watermark.threadId !== threadId) throw new Error("No trusted pre-send rollout watermark is available");
    const cwd = canonicalDirectory(expectedCwd, "The selected native task workspace");
    if (watermark.cwd !== cwd) throw new Error("The selected native task workspace changed after dispatch");
    const found = findRollout(threadId, env);
    if (found.file !== watermark.file) throw new Error("The selected native task rollout changed after dispatch");
    const snapshot = readStable(found, maxRolloutBytes);
    if (snapshot.identity.dev !== watermark.identity?.dev || snapshot.identity.ino !== watermark.identity?.ino || snapshot.data.length < watermark.size) throw new Error("The selected native task rollout identity changed after dispatch");
    const prefix = snapshot.data.subarray(0, watermark.size);
    if (crypto.createHash("sha256").update(prefix).digest("hex") !== watermark.prefixSha256) throw new Error("The pre-send Codex rollout history changed after dispatch");
    const records = parseRecords(snapshot.data);
    validateSession(records, threadId, cwd);
    const tail = records.filter(({ start }) => start >= watermark.size);
    const forTurn = ({ record }) => {
      const metadata = object(record.payload?.internal_chat_message_metadata_passthrough) ? record.payload.internal_chat_message_metadata_passthrough : {};
      const turnFields = [record.payload?.turn_id, record.payload?.root_turn_id, metadata.turn_id, metadata.root_turn_id].filter((value) => value !== undefined);
      if (!turnFields.includes(turnId)) return false;
      if (turnFields.some((value) => value !== turnId)) throw new Error("The native response contains contradictory turn identity");
      const threadFields = [record.payload?.thread_id, metadata.thread_id].filter((value) => value !== undefined);
      if (threadFields.some((value) => value !== threadId)) throw new Error("The native response contains contradictory task identity");
      return true;
    };
    const turns = tail.filter(forTurn);
    const starts = turns.filter(({ record }) => record.type === "event_msg" && STARTED.has(record.payload.type));
    const contexts = turns.filter(({ record }) => record.type === "turn_context");
    if (starts.length !== 1 || contexts.length !== 1 || canonicalDirectory(contexts[0].record.payload.cwd, "The observed turn workspace") !== cwd) throw new Error("The newly observed turn identity is incomplete or ambiguous");
    const dispatches = turns.filter(({ record }) => record.type === "response_item" && record.payload.type === "function_call_output" &&
      record.payload.namespace === "codex_app" && record.payload.name === "send_message_to_thread");
    if (dispatches.length !== 1 || dispatches[0].record.payload.output !== delegationOutput(executorThreadId, prompt)) throw new Error("The newly observed turn is not correlated to the exact native dispatch");
    const finals = turns.filter(({ record }) => record.type === "response_item" && record.payload.type === "message" &&
      record.payload.role === "assistant" && record.payload.phase === "final_answer");
    const completions = turns.filter(({ record }) => record.type === "event_msg" && COMPLETED.has(record.payload.type));
    const failures = turns.filter(({ record }) => record.type === "event_msg" && (FAILED.has(record.payload.type) || record.payload.error || ["failed", "aborted", "interrupted"].includes(record.payload.status)));
    if (failures.length || finals.length !== 1 || completions.length !== 1 || starts[0].start >= dispatches[0].start || contexts[0].start >= dispatches[0].start || dispatches[0].start >= finals[0].start || finals[0].start >= completions[0].start) throw new Error("The native final response is missing, ambiguous, failed, or out of order");
    const content = finals[0].record.payload.content;
    if (!Array.isArray(content) || !content.length || content.some((item) => !object(item) || item.type !== "output_text" || typeof item.text !== "string")) throw new Error("The native final response contains unsupported content");
    const text = content.map((item) => item.text).join("");
    if (!text.trim() || Buffer.byteLength(text, "utf8") > MAX_REPLY_BYTES) throw new Error("The native final response is empty or exceeds the bounded reply limit");
    return { status: "available", text, turnId };
  } catch (error) {
    return unavailable(error);
  }
}
