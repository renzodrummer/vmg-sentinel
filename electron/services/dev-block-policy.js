const { createPrivateKey, sign } = require('node:crypto');
const { serializeUnsigned } = require('./policy-document');

const DEV_SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

function privateKeyFromSeed(seedHex) {
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(seedHex, 'hex'),
  ]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function envFlag(name, env = process.env) {
  return ['1', 'true', 'TRUE', 'yes', 'YES'].includes(String(env[name] || ''));
}

/** Signed local deny list until Citadel provides one. Set VMG_SENTINEL_DEV_POLICY=0 to disable. */
function shouldApplyLocalDevPolicy({ env = process.env } = {}) {
  return env.VMG_SENTINEL_DEV_POLICY !== '0';
}

/** Electron never elevates. On Windows it must attach to an already-running admin helper. */
function shouldSpawnHelper({
  isPackaged,
  env = process.env,
  platform = process.platform,
} = {}) {
  if (env.VMG_SENTINEL_SPAWN_HELPER === '0') {
    return false;
  }
  if (envFlag('VMG_SENTINEL_SPAWN_HELPER', env)) {
    return true;
  }
  if (isPackaged) {
    return false;
  }
  // A user-level spawn cannot create firewall rules and often dies with Access denied
  // if an admin helper already owns the pipe.
  if (platform === 'win32') {
    return false;
  }
  return true;
}

function createDefaultWorkPolicy() {
  const unsigned = {
    version: 1,
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    ttl_seconds: 60 * 60 * 24 * 7,
    mode: 'block',
    sites: {
      allow: [],
      deny: [
        'facebook.com',
        'youtube.com',
        'instagram.com',
        'tiktok.com',
        'reddit.com',
        'redditstatic.com',
        'redditmedia.com',
        'redd.it',
        'twitter.com',
        'x.com',
      ],
    },
    apps: {
      deny: [
        { kind: 'path', value: 'steam.exe' },
        { kind: 'path', value: 'spotify.exe' },
      ],
    },
  };
  const key = privateKeyFromSeed(DEV_SEED_HEX);
  const signature = sign(null, serializeUnsigned(unsigned), key).toString('hex');
  return { ...unsigned, signature };
}

module.exports = {
  createDefaultWorkPolicy,
  shouldApplyLocalDevPolicy,
  shouldSpawnHelper,
};
