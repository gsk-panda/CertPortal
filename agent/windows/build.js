'use strict';

/**
 * Builds the Windows agent: one self-contained certportal-agent.exe (a Node
 * single executable application), the WinSW service wrapper, and — with
 * --msi — certportal-agent.msi. Runs on Linux or macOS; --msi needs msitools
 * (wixl, msibuild), e.g. `apt install wixl msitools`.
 *
 *   cd agent && npm install && node windows/build.js [--msi | --msi-only]
 *
 * The exe embeds the Node runtime that runs this script (the SEA blob and the
 * node.exe it is injected into must be the same version), so build with the
 * Node version you want to ship. Output goes to agent/windows/dist/.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const AGENT_DIR = path.resolve(__dirname, '..');
const DIST = path.join(__dirname, 'dist');
const WORK = path.join(DIST, 'build');
const VERSION = require('../package.json').version;

// WinSW 2.12.0 (self-contained x64 build), pinned by hash
const WINSW_URL = 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe';
const WINSW_SHA256 = '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da';
const SEA_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function download(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

function run(cmd, args, opts = {}) {
  execFileSync(cmd, args, { stdio: 'inherit', ...opts });
}

async function nodeExe() {
  const base = `https://nodejs.org/dist/${process.version}`;
  const [exe, sums] = await Promise.all([download(`${base}/win-x64/node.exe`), download(`${base}/SHASUMS256.txt`)]);
  const line = sums.toString().split('\n').find((l) => l.trim().endsWith(' win-x64/node.exe'));
  if (!line || line.split(/\s+/)[0] !== sha256(exe)) throw new Error('node.exe checksum mismatch');
  return exe;
}

// node.exe is signed by the OpenJS Foundation; injecting the blob breaks that
// signature, so drop it (CI re-signs with ours when signing is configured).
// PE32+: the certificate table is data directory 4 and sits at the end of the file.
function stripPeSignature(buf) {
  const opt = buf.readUInt32LE(0x3c) + 24;             // optional header
  if (buf.readUInt16LE(opt) !== 0x20b) throw new Error('node.exe is not PE32+');
  const dir = opt + 112 + 4 * 8;                       // IMAGE_DIRECTORY_ENTRY_SECURITY
  const offset = buf.readUInt32LE(dir);
  const size = buf.readUInt32LE(dir + 4);
  if (!size) return buf;
  if (offset + size !== buf.length) throw new Error('unexpected certificate table position');
  const out = Buffer.from(buf.subarray(0, offset));
  out.writeUInt32LE(0, dir);
  out.writeUInt32LE(0, dir + 4);
  out.writeUInt32LE(0, opt + 64);                      // checksum
  return out;
}

// wixl can't express these, so patch the tables it wrote:
//  - public properties must be listed as secure or an elevated (UAC) install
//    drops them before the custom actions see them
//  - HideTarget (0x2000) keeps the enrollment token out of verbose install logs
function fixMsi(msi) {
  const q = (sql) => run('msibuild', [msi, '-q', sql]);
  q("UPDATE `Property` SET `Value` = 'CONTROL_PLANE_URL;ENROLL_TOKEN;AGENT_NAME;WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED' WHERE `Property` = 'SecureCustomProperties'");
  q("UPDATE `CustomAction` SET `Type` = 11282 WHERE `Action` = 'ConfigureAgent'"); // 18 exe + deferred + no-impersonate + HideTarget
}

async function main() {
  // --msi-only packages an existing dist/ (e.g. after signing the exes)
  if (process.argv.includes('--msi-only')) return buildMsi();
  fs.rmSync(DIST, { recursive: true, force: true });
  fs.mkdirSync(WORK, { recursive: true });

  // 1. bundle the agent + shared PAN-OS modules into one CommonJS file. The
  //    shared modules live under ../src and resolve their deps from here.
  const esbuild = require('esbuild');
  await esbuild.build({
    entryPoints: [path.join(AGENT_DIR, 'index.js')],
    bundle: true,
    platform: 'node',
    target: `node${process.versions.node.split('.')[0]}`,
    nodePaths: [path.join(AGENT_DIR, 'node_modules')],
    outfile: path.join(WORK, 'agent.cjs'),
    logLevel: 'warning',
  });

  // 2. SEA blob
  const seaConfig = path.join(WORK, 'sea-config.json');
  fs.writeFileSync(seaConfig, JSON.stringify({
    main: path.join(WORK, 'agent.cjs'),
    output: path.join(WORK, 'sea-prep.blob'),
    disableExperimentalSEAWarning: true,
    useCodeCache: false, // code cache is platform-specific; we may cross-build
  }));
  run(process.execPath, ['--experimental-sea-config', seaConfig]);

  // 3. inject it into the official node.exe of the same version
  const exePath = path.join(DIST, 'certportal-agent.exe');
  fs.writeFileSync(exePath, stripPeSignature(await nodeExe()));
  const { inject } = require('postject');
  await inject(exePath, 'NODE_SEA_BLOB', fs.readFileSync(path.join(WORK, 'sea-prep.blob')), { sentinelFuse: SEA_FUSE });

  // 4. service wrapper: WinSW reads the .xml with its own base name
  const winsw = await download(WINSW_URL);
  if (sha256(winsw) !== WINSW_SHA256) throw new Error('WinSW checksum mismatch');
  fs.writeFileSync(path.join(DIST, 'certportal-agent-service.exe'), winsw);
  fs.copyFileSync(path.join(__dirname, 'certportal-agent-service.xml'), path.join(DIST, 'certportal-agent-service.xml'));

  console.log(`built certportal-agent.exe ${VERSION} (Node ${process.version})`);

  if (process.argv.includes('--msi')) buildMsi();
}

function buildMsi() {
  const msi = path.join(DIST, 'certportal-agent.msi');
  run('wixl', ['-a', 'x64',
    '-D', `Version=${VERSION}`,
    '-D', `DistDir=${DIST}`,
    '-D', `ControlPlaneUrl=${process.env.CONTROL_PLANE_URL || 'https://certportal.azotech.net'}`,
    '-o', msi, path.join(__dirname, 'certportal-agent.wxs')]);
  fixMsi(msi);
  console.log('built certportal-agent.msi');
}

main().catch((err) => { console.error(err); process.exit(1); });
