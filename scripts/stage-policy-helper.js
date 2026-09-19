const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '../native/policy-helper');
const binDir = path.join(root, 'bin');
const exe = process.platform === 'win32' ? 'vmg-sentinel-helper.exe' : 'vmg-sentinel-helper';
const dest = path.join(binDir, exe);

function copyIfExists(from) {
  if (!fs.existsSync(from)) {
    return false;
  }
  fs.mkdirSync(binDir, { recursive: true });
  fs.copyFileSync(from, dest);
  console.log(`staged ${from} -> ${dest}`);
  return true;
}

const candidates = [
  path.join(root, 'target/rebuild/release', exe),
  path.join(root, 'target/release', exe),
];
if (candidates.some((file) => copyIfExists(file))) {
  process.exit(0);
}

const cargoArgs = [
  'build',
  '--release',
  '--manifest-path',
  path.join(root, 'Cargo.toml'),
  '--target-dir',
  path.join(root, 'target/rebuild'),
];
const cargo = spawnSync('cargo', cargoArgs, { stdio: 'inherit', shell: process.platform === 'win32' });
if (cargo.status !== 0) {
  process.exit(cargo.status ?? 1);
}
if (!copyIfExists(path.join(root, 'target/rebuild/release', exe))) {
  console.error('helper binary missing after cargo build');
  process.exit(1);
}
