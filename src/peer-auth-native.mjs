import fs from "node:fs";
import path from "node:path";
import { matchDesktopProject } from "./thread-delivery.mjs";

function samePath(first, second) {
  return path.relative(fs.realpathSync.native(first), fs.realpathSync.native(second)) === "";
}

export async function assertNativeCodexPeer({ relay, identity, accountContext, beforeSend, timeoutMs } = {}) {
  if (!relay || !identity || identity.agent !== "codex") throw new Error("Native Codex peer identity is missing");
  const options = { accountContext, beforeSend, ...(timeoutMs ? { timeoutMs } : {}) };
  const projects = (await relay.requestDesktop("list_projects", {}, options)).result;
  const project = matchDesktopProject(projects?.projects ?? [], identity.canonical_cwd);
  if (project.projectId !== identity.project_id) throw Object.assign(new Error("Native Codex project changed from the peer grant"), { code: "WRONG_PROJECT" });
  const read = (await relay.requestDesktop("read_thread", { threadId: identity.task_id, hostId: "local", turnLimit: 1 }, options)).result;
  if (read?.thread?.id !== identity.task_id || read.thread.hostId !== "local" || !samePath(read.thread.cwd, identity.canonical_cwd) || (read.thread.projectId && read.thread.projectId !== identity.project_id)) throw Object.assign(new Error("Native Codex task changed from the peer grant"), { code: "WRONG_TASK" });
  const listedResult = (await relay.requestDesktop("list_threads", { limit: 50 }, options)).result;
  const listed = [...(listedResult?.pinnedThreads ?? []), ...(listedResult?.threads ?? [])].filter((thread) => thread.id === identity.task_id && thread.hostId === "local" && thread.projectId === identity.project_id && samePath(thread.cwd, identity.canonical_cwd));
  if (listed.length !== 1) throw Object.assign(new Error("Native Codex task/project membership is missing or ambiguous"), { code: "WRONG_PROJECT" });
  return identity;
}
