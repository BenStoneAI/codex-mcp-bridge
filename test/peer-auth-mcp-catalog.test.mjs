import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { PeerAuthKeyStore } from "../src/peer-auth-keystore-win32.mjs";
import { PeerAuthStore } from "../src/peer-auth-store.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "peer-auth-catalog-"));
const authRoot = path.join(sandbox, "auth");
const cwd = fs.realpathSync.native(sandbox); const stat = fs.statSync(cwd, { bigint: true }); const cwdIdentity = `${stat.dev}:${stat.ino}`;

describe("authenticated peer MCP catalogs", () => {
  before(() => {
    assert.equal(process.platform, "win32", "Required DPAPI acceptance must run on Windows");
    const keys = new PeerAuthKeyStore({ root: authRoot }); keys.setup();
    const store = new PeerAuthStore({ root: authRoot, validateStorage: (paths) => keys.validatePaths(paths), protectStorage: (paths) => keys.protectPaths(paths) });
    for (const [agent, taskId, sessionId] of [["claude", `local_${crypto.randomUUID()}`, "session"], ["codex", crypto.randomUUID(), ""]]) store.provisionGrant({ agent, accountFingerprint: `${agent}-account`, taskId, sessionId, cwd, cwdIdentity, projectId: crypto.randomUUID(), capabilityCeiling: "review_only" });
    store.close();
  });
  after(() => fs.rmSync(sandbox, { recursive: true, force: true }));

  for (const entry of ["index.mjs", "claude-bridge.mjs"]) it(`loads the three peer tools from the real ${entry} server and blocks adjacent raw creation`, async () => {
    const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(repo, "src", entry)], env: { PATH: process.env.PATH ?? "", HOME: sandbox, USERPROFILE: sandbox, APPDATA: path.join(sandbox, "AppData", "Roaming"), LOCALAPPDATA: path.join(sandbox, "AppData", "Local"), CODEX_HOME: path.join(sandbox, ".codex"), CODEX_BRIDGE_PEER_AUTH: "1", CODEX_BRIDGE_PEER_AUTH_DIR: authRoot, CODEX_BRIDGE_DESKTOP_TASKS: "0", CODEX_BRIDGE_AUTOSTART: "0", CODEX_BRIDGE_NATIVE_RELAY: "0" }, stderr: "ignore" });
    const client = new Client({ name: "peer-auth-catalog-test", version: "1" });
    try {
      await client.connect(transport);
      const catalog = await client.listTools(); const names = catalog.tools.map((tool) => tool.name);
      for (const name of ["verify_peer_message", "reply_to_peer_message", "read_peer_reply"]) assert.ok(names.includes(name), `${entry} missing ${name}`);
      const send = catalog.tools.find((tool) => tool.name === (entry === "index.mjs" ? "send_to_codex_thread" : "send_to_claude_session"));
      assert.ok(send.inputSchema.properties.requested_capability); assert.ok(send.inputSchema.properties.parent_message_id);
      if (entry === "index.mjs") {
        const blockedSend = await client.callTool({ name: "send_to_codex_thread", arguments: { threadId: crypto.randomUUID(), prompt: "raw" } });
        assert.equal(blockedSend.isError, true); assert.match(blockedSend.content[0].text, /Authenticated peer mode/);
        for (const name of ["delegate_to_codex", "start_codex_thread"]) {
          const blocked = await client.callTool({ name, arguments: name === "delegate_to_codex" ? { cwd, prompt: "raw" } : { cwd, prompt: "raw" } });
          assert.equal(blocked.isError, true); assert.match(blocked.content[0].text, /Authenticated peer mode/);
        }
      }
    } finally { await client.close(); }
  });
});
