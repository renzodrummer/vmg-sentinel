const fs = require('node:fs');
const path = require('node:path');

const REQUIRED_BUILD = 'fw-4';
const ALLOW_ALL = 'VMG Sentinel allow all';

const root = path.join(__dirname, '..');
const lib = fs.readFileSync(
  path.join(root, 'native/policy-helper/src/lib.rs'),
  'utf8',
);
const client = fs.readFileSync(
  path.join(root, 'electron/services/policy-helper-client.js'),
  'utf8',
);
const exeName =
  process.platform === 'win32' ? 'vmg-sentinel-helper.exe' : 'vmg-sentinel-helper';
const staged = path.join(root, 'native/policy-helper/bin', exeName);

const libBuild = lib.match(/HELPER_BUILD:\s*&str\s*=\s*"([^"]+)"/)?.[1];
const clientBuild = client.match(/EXPECTED_HELPER_BUILD\s*=\s*'([^']+)'/)?.[1];

function fail(message) {
  console.error(`verify-helper-safe: ${message}`);
  process.exit(1);
}

if (libBuild !== REQUIRED_BUILD) {
  fail(`lib.rs HELPER_BUILD is ${libBuild}, expected ${REQUIRED_BUILD}`);
}
if (clientBuild !== REQUIRED_BUILD) {
  fail(
    `policy-helper-client.js EXPECTED_HELPER_BUILD is ${clientBuild}, expected ${REQUIRED_BUILD}`,
  );
}
if (!fs.existsSync(staged)) {
  fail(`staged helper missing: ${staged} (run npm run build:helper)`);
}

const bytes = fs.readFileSync(staged);
if (!bytes.includes(Buffer.from(REQUIRED_BUILD))) {
  fail(`staged exe does not contain ${REQUIRED_BUILD}; refuse to package a pre-fw-4 helper`);
}
if (!bytes.includes(Buffer.from(ALLOW_ALL))) {
  fail(`staged exe is missing "${ALLOW_ALL}"; deny-only AppLocker must not ship`);
}

console.log(`verify-helper-safe: ok (${REQUIRED_BUILD}, allow-all present)`);
console.log(`  ${staged}`);
