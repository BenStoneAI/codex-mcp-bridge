import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const AGENTS = new Set(["claude", "codex"]);
const MAX_KEY_FILE = 16384;

function encodedPowerShell(script) { return Buffer.from(script, "utf16le").toString("base64"); }
function powershellPath(env = process.env) { return path.join(env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"); }

function runPowerShell(script, { input = "", env = process.env } = {}) {
  const systemModules = path.join(env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "Modules");
  const cleanEnv = { ...env, PSModulePath: systemModules };
  const result = spawnSync(powershellPath(env), ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(`$ErrorActionPreference='Stop';$env:PSModulePath='${systemModules.replace(/'/g, "''")}';${script}`)], {
    input, encoding: "utf8", windowsHide: true, maxBuffer: 65536, env: cleanEnv,
  });
  if (result.status !== 0) throw new Error("Windows protected-key operation failed");
  return result.stdout.trim();
}

export function dpapiProtectCurrentUser(bytes, options = {}) {
  if (!Buffer.isBuffer(bytes) || !bytes.length) throw new Error("Private key material is missing");
  const output = runPowerShell("Add-Type -AssemblyName System.Security;$value=[Console]::In.ReadToEnd().Trim();$plain=[Convert]::FromBase64String($value);try{$protected=[Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);[Console]::Out.Write([Convert]::ToBase64String($protected))}finally{[Array]::Clear($plain,0,$plain.Length)}", { ...options, input: bytes.toString("base64") });
  return Buffer.from(output, "base64");
}

export function dpapiUnprotectCurrentUser(bytes, options = {}) {
  if (!Buffer.isBuffer(bytes) || !bytes.length) throw new Error("Protected key material is missing");
  const output = runPowerShell("Add-Type -AssemblyName System.Security;$value=[Console]::In.ReadToEnd().Trim();$protected=[Convert]::FromBase64String($value);$plain=[Security.Cryptography.ProtectedData]::Unprotect($protected,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);try{[Console]::Out.Write([Convert]::ToBase64String($plain))}finally{[Array]::Clear($plain,0,$plain.Length)}", { ...options, input: bytes.toString("base64") });
  return Buffer.from(output, "base64");
}

function pathArrayLiteral(value) {
  const values = Array.isArray(value) ? value : [value];
  if (!values.length || values.some((candidate) => typeof candidate !== "string" || !path.isAbsolute(candidate))) throw new Error("Peer authentication ACL paths must be absolute");
  return `@(${values.map((candidate) => `'${candidate.replace(/'/g, "''")}'`).join(",")})`;
}

export function protectPeerAuthAcl(paths, options = {}) {
  const literal = pathArrayLiteral(paths);
  runPowerShell(`$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;foreach($p in ${literal}){$acl=Get-Acl -LiteralPath $p;$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);foreach($r in @($acl.Access)){$acl.RemoveAccessRuleSpecific($r)};$flags=if((Get-Item -LiteralPath $p -Force).PSIsContainer){'ContainerInherit,ObjectInherit'}else{'None'};$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl',$flags,'None','Allow');$acl.AddAccessRule($rule)|Out-Null;Set-Acl -LiteralPath $p -AclObject $acl}`, options);
}

export function assertPeerAuthAcl(paths, options = {}) {
  const literal = pathArrayLiteral(paths);
  const output = runPowerShell(`$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$states=@(foreach($p in ${literal}){$item=Get-Item -LiteralPath $p -Force;$acl=Get-Acl -LiteralPath $p;$owner=(New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;$rows=@($acl.Access|ForEach-Object{@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;type=$_.AccessControlType.ToString();rights=$_.FileSystemRights.ToString();inherited=$_.IsInherited}});@{path=$p;owner=$owner;sid=$sid;protected=$acl.AreAccessRulesProtected;reparse=(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0);rows=$rows}});[Console]::Out.Write((ConvertTo-Json -InputObject $states -Compress -Depth 4))`, options);
  const parsed = JSON.parse(output);
  const states = Array.isArray(parsed) ? parsed : [parsed];
  if (states.length !== (Array.isArray(paths) ? paths.length : 1) || states.some((state) => state.reparse || state.owner !== state.sid || !state.protected || !Array.isArray(state.rows) || state.rows.length !== 1 || state.rows[0].sid !== state.sid || state.rows[0].type !== "Allow" || state.rows[0].inherited || !String(state.rows[0].rights).includes("FullControl"))) throw new Error("Peer authentication ACL, owner, or path is not current-user-only");
}

function assertSafePath(candidate, kind) {
  const status = fs.lstatSync(candidate);
  if (status.isSymbolicLink() || (kind === "directory" ? !status.isDirectory() : !status.isFile())) throw new Error(`Peer authentication ${kind} is not regular`);
  if (kind === "file" && status.nlink !== 1) throw new Error("Peer authentication file has an unsafe hard-link count");
  return status;
}

function assertWithinRoot(root, candidate) {
  const relative = path.relative(root, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Peer authentication path escapes its protected root");
  for (const segment of [root, ...relative.split(path.sep).filter(Boolean).map((_, index, parts) => path.join(root, ...parts.slice(0, index + 1)))]) {
    const status = fs.lstatSync(segment);
    if (status.isSymbolicLink()) throw new Error("Peer authentication path contains a reparse point");
    const canonical = fs.realpathSync.native(segment);
    if (process.platform === "win32" ? canonical.toLowerCase() !== path.resolve(segment).toLowerCase() : canonical !== path.resolve(segment)) {
      throw new Error("Peer authentication path canonical identity changed");
    }
  }
}

function assertSetupRootCandidate(root) {
  let existing = root;
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) throw new Error("Peer authentication root has no existing canonical ancestor");
    existing = parent;
  }
  const status = fs.lstatSync(existing);
  const canonical = fs.realpathSync.native(existing);
  const equal = process.platform === "win32" ? canonical.toLowerCase() === path.resolve(existing).toLowerCase() : canonical === path.resolve(existing);
  if (!status.isDirectory() || status.isSymbolicLink() || !equal) throw new Error("Peer authentication setup root contains a reparse point");
  if (fs.existsSync(root)) {
    assertWithinRoot(root, root); assertSafePath(root, "directory");
    if (fs.readdirSync(root).length) throw new Error("Peer authentication setup root is not empty; setup never overwrites identities");
  }
}

function readStableFile(file, maxBytes = MAX_KEY_FILE) {
  const beforePath = assertSafePath(file, "file");
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(fd);
    if (before.dev !== beforePath.dev || before.ino !== beforePath.ino || before.size < 1 || before.size > maxBytes) throw new Error("Peer authentication file identity or size is invalid");
    const data = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(fd, data, offset, data.length - offset, offset);
      if (!count) throw new Error("Peer authentication file changed while reading");
      offset += count;
    }
    const after = fs.fstatSync(fd);
    const afterPath = assertSafePath(file, "file");
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.dev !== afterPath.dev || before.ino !== afterPath.ino) throw new Error("Peer authentication file changed while reading");
    return data;
  } finally { fs.closeSync(fd); }
}

function exclusiveWrite(file, data) {
  const fd = fs.openSync(file, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

export class PeerAuthKeyStore {
  constructor({ root, protect = dpapiProtectCurrentUser, unprotect = dpapiUnprotectCurrentUser, protectAcl = protectPeerAuthAcl, validateAcl = assertPeerAuthAcl, platform = process.platform } = {}) {
    if (typeof root !== "string" || !path.isAbsolute(root)) throw new Error("CODEX_BRIDGE_PEER_AUTH_DIR must be an explicit absolute directory");
    this.root = path.resolve(root); this.keysDir = path.join(this.root, "keys"); this.pinsFile = path.join(this.root, "peer-pins.json");
    this.protect = protect; this.unprotect = unprotect; this.protectAcl = protectAcl; this.validateAcl = validateAcl; this.platform = platform;
  }

  setup() {
    if (this.platform !== "win32") throw new Error("Persistent peer identities require Windows DPAPI CurrentUser");
    assertSetupRootCandidate(this.root);
    fs.mkdirSync(this.root, { recursive: true });
    assertWithinRoot(this.root, this.root); assertSafePath(this.root, "directory");
    this.protectAcl(this.root);
    this.validateAcl(this.root);
    fs.mkdirSync(this.keysDir);
    this.protectAcl(this.keysDir);
    const identities = {};
    for (const agent of AGENTS) {
      const keyFile = path.join(this.keysDir, `${agent}-side-bridge.dpapi`);
      if (fs.existsSync(keyFile)) throw new Error(`Peer identity ${agent} already exists; setup never overwrites identities`);
      const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
      const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
      const spki = publicKey.export({ type: "spki", format: "der" });
      try { exclusiveWrite(keyFile, this.protect(pkcs8)); } finally { pkcs8.fill(0); }
      this.protectAcl(keyFile);
      identities[agent] = { key_id: crypto.createHash("sha256").update(spki).digest("hex"), public_key: spki.toString("base64") };
    }
    exclusiveWrite(this.pinsFile, Buffer.from(`${JSON.stringify({ version: 1, identities }, null, 2)}\n`, "utf8"));
    this.protectAcl(this.pinsFile);
    this.validate();
    return { root: this.root, identities: Object.fromEntries(Object.entries(identities).map(([agent, value]) => [agent, { key_id: value.key_id }])) };
  }

  validate() {
    const protectedPaths = [this.root, this.keysDir, this.pinsFile, ...[...AGENTS].map((agent) => path.join(this.keysDir, `${agent}-side-bridge.dpapi`))];
    assertWithinRoot(this.root, this.root); assertWithinRoot(this.root, this.keysDir);
    assertSafePath(this.root, "directory"); assertSafePath(this.keysDir, "directory"); assertSafePath(this.pinsFile, "file");
    for (const agent of AGENTS) {
      const keyFile = path.join(this.keysDir, `${agent}-side-bridge.dpapi`);
      assertWithinRoot(this.root, keyFile); assertSafePath(keyFile, "file");
    }
    assertWithinRoot(this.root, this.pinsFile); this.validateAcl(protectedPaths);
    const pins = this.#pins();
    for (const agent of AGENTS) if (!pins.identities[agent]) throw new Error(`Pinned ${agent} identity is missing`);
    return true;
  }

  validatePath(candidate) {
    assertWithinRoot(this.root, candidate);
    const kind = fs.lstatSync(candidate).isDirectory() ? "directory" : "file";
    assertSafePath(candidate, kind); this.validateAcl(candidate); return true;
  }

  validatePaths(candidates) { for (const candidate of candidates) { assertWithinRoot(this.root, candidate); assertSafePath(candidate, fs.lstatSync(candidate).isDirectory() ? "directory" : "file"); } this.validateAcl(candidates); return true; }

  protectPath(candidate) { this.protectAcl(candidate); return this.validatePath(candidate); }
  protectPaths(candidates) { this.protectAcl(candidates); return this.validatePaths(candidates); }

  #pins() {
    const pins = JSON.parse(readStableFile(this.pinsFile).toString("utf8"));
    if (pins?.version !== 1 || !pins.identities || Object.keys(pins.identities).length !== 2) throw new Error("Peer public pins are invalid");
    for (const agent of AGENTS) {
      const entry = pins.identities[agent];
      if (!entry || typeof entry.key_id !== "string" || !/^[0-9a-f]{64}$/.test(entry.key_id) || typeof entry.public_key !== "string") throw new Error("Peer public pin is invalid");
      const spki = Buffer.from(entry.public_key, "base64");
      if (crypto.createHash("sha256").update(spki).digest("hex") !== entry.key_id) throw new Error("Peer public pin fingerprint does not match");
    }
    return pins;
  }

  publicIdentity(agent) {
    if (!AGENTS.has(agent)) throw new Error("Unknown peer agent");
    this.validate();
    const entry = this.#pins().identities[agent];
    return { keyId: entry.key_id, publicKey: crypto.createPublicKey({ key: Buffer.from(entry.public_key, "base64"), type: "spki", format: "der" }) };
  }

  publicIdentities() {
    this.validate();
    const pins = this.#pins();
    return Object.fromEntries([...AGENTS].map((agent) => {
      const entry = pins.identities[agent];
      return [agent, { keyId: entry.key_id, publicKey: crypto.createPublicKey({ key: Buffer.from(entry.public_key, "base64"), type: "spki", format: "der" }) }];
    }));
  }

  withPrivateIdentity(agent, callback) {
    if (!AGENTS.has(agent) || typeof callback !== "function") throw new Error("Invalid private peer identity request");
    this.validate();
    const protectedBytes = readStableFile(path.join(this.keysDir, `${agent}-side-bridge.dpapi`));
    const plain = this.unprotect(protectedBytes);
    protectedBytes.fill(0);
    try {
      const privateKey = crypto.createPrivateKey({ key: plain, type: "pkcs8", format: "der" });
      const entry = this.#pins().identities[agent];
      const own = { keyId: entry.key_id, publicKey: crypto.createPublicKey({ key: Buffer.from(entry.public_key, "base64"), type: "spki", format: "der" }) };
      const derived = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
      const pinned = own.publicKey.export({ type: "spki", format: "der" });
      if (!Buffer.from(derived).equals(Buffer.from(pinned))) throw new Error("Protected private identity does not match its pinned public key");
      return callback({ privateKey, keyId: own.keyId });
    } finally { plain.fill(0); }
  }
}

export function peerAuthEnabled(env = process.env) {
  return env.CODEX_BRIDGE_PEER_AUTH === "1";
}

export function peerAuthDirectory(env = process.env) {
  if (!peerAuthEnabled(env)) return null;
  if (!env.CODEX_BRIDGE_PEER_AUTH_DIR || !path.isAbsolute(env.CODEX_BRIDGE_PEER_AUTH_DIR)) throw new Error("CODEX_BRIDGE_PEER_AUTH=1 requires an explicit absolute CODEX_BRIDGE_PEER_AUTH_DIR");
  return path.resolve(env.CODEX_BRIDGE_PEER_AUTH_DIR);
}
