const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '../native/policy-helper');
const binDir = path.join(root, 'bin');
const exe = process.platform === 'win32' ? 'vmg-sentinel-helper.exe' : 'vmg-sentinel-helper';
const dest = path.join(binDir, exe);
const rebuildDir = path.join(root, 'target/rebuild');
const rebuildExe = path.join(rebuildDir, 'release', exe);

function currentHelperBuild() {
  const lib = fs.readFileSync(path.join(root, 'src/lib.rs'), 'utf8');
  const match = lib.match(/HELPER_BUILD:\s*&str\s*=\s*"([^"]+)"/);
  return match ? match[1] : null;
}

function binaryHasAscii(file, needle) {
  if (!needle || !fs.existsSync(file)) {
    return false;
  }
  return fs.readFileSync(file).includes(Buffer.from(needle));
}

const expected = currentHelperBuild();
if (expected !== 'fw-4') {
  console.error(`refusing to stage: HELPER_BUILD in lib.rs is ${expected}, expected fw-4`);
  process.exit(1);
}

const cargo = spawnSync(
  'cargo',
  [
    'build',
    '--release',
    '--manifest-path',
    path.join(root, 'Cargo.toml'),
    '--target-dir',
    rebuildDir,
  ],
  { stdio: 'inherit', shell: process.platform === 'win32' },
);
if (cargo.status !== 0) {
  process.exit(cargo.status ?? 1);
}
if (!fs.existsSync(rebuildExe)) {
  console.error('helper binary missing after cargo build');
  process.exit(1);
}
if (!binaryHasAscii(rebuildExe, 'fw-4')) {
  console.error('refusing to stage: rebuilt exe does not contain fw-4');
  process.exit(1);
}
if (!binaryHasAscii(rebuildExe, 'VMG Sentinel allow all')) {
  console.error(
    'refusing to stage: rebuilt exe is missing the AppLocker allow-all safety string',
  );
  process.exit(1);
}

fs.mkdirSync(binDir, { recursive: true });
fs.copyFileSync(rebuildExe, dest);
console.log(`staged ${rebuildExe} -> ${dest} (fw-4, allow-all present)`);
