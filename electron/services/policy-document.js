const { createPublicKey, verify } = require('node:crypto');
const { mergeSiteAllow } = require('./policy-seed-allowlist');

const DEV_PUBLIC_KEY_HEX =
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

function serializeUnsigned(policy) {
  const body = {
    version: policy.version,
    issued_at: policy.issued_at,
    ttl_seconds: policy.ttl_seconds,
    mode: policy.mode,
    sites: {
      allow: policy.sites?.allow ?? [],
      deny: policy.sites?.deny ?? [],
    },
    apps: {
      deny: (policy.apps?.deny ?? []).map((rule) =>
        rule.alg
          ? { kind: rule.kind, alg: rule.alg, value: rule.value }
          : { kind: rule.kind, value: rule.value },
      ),
    },
  };
  return Buffer.from(JSON.stringify(body), 'utf8');
}

function verifyingKey(publicKeyHex) {
  const header = Buffer.from('302a300506032b6570032100', 'hex');
  const spki = Buffer.concat([header, Buffer.from(publicKeyHex.trim(), 'hex')]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

function isExpired(policy, nowMs = Date.now()) {
  const issued = Date.parse(policy.issued_at);
  if (Number.isNaN(issued)) {
    return true;
  }
  return nowMs >= issued + Number(policy.ttl_seconds) * 1000;
}

function parseAndVerify(raw, publicKeyHex = DEV_PUBLIC_KEY_HEX, nowMs = Date.now()) {
  let doc;
  try {
    doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return { ok: false, code: 'POLICY_INVALID' };
  }

  if (!doc || typeof doc !== 'object') {
    return { ok: false, code: 'POLICY_INVALID' };
  }
  if (!Number.isInteger(doc.version) || doc.version < 1) {
    return { ok: false, code: 'POLICY_INVALID' };
  }
  if (doc.mode !== 'audit' && doc.mode !== 'block') {
    return { ok: false, code: 'POLICY_INVALID' };
  }
  if (!doc.signature) {
    return { ok: false, code: 'POLICY_UNSIGNED' };
  }

  for (const rule of doc.apps?.deny ?? []) {
    if (rule.kind === 'hash' && String(rule.alg || '').toLowerCase() !== 'sha256') {
      return { ok: false, code: 'POLICY_INVALID' };
    }
  }

  let signature;
  try {
    signature = Buffer.from(doc.signature, 'hex');
  } catch {
    return { ok: false, code: 'POLICY_BAD_SIGNATURE' };
  }

  const payload = serializeUnsigned(doc);
  let good = false;
  try {
    good = verify(null, payload, verifyingKey(publicKeyHex), signature);
  } catch {
    return { ok: false, code: 'POLICY_BAD_SIGNATURE' };
  }
  if (!good) {
    return { ok: false, code: 'POLICY_BAD_SIGNATURE' };
  }
  if (isExpired(doc, nowMs)) {
    return { ok: false, code: 'POLICY_EXPIRED' };
  }

  return {
    ok: true,
    policy: {
      ...doc,
      sites: {
        allow: mergeSiteAllow(doc.sites?.allow ?? []),
        deny: doc.sites?.deny ?? [],
      },
      apps: { deny: doc.apps?.deny ?? [] },
    },
  };
}

function effectiveMode(policy, nowMs = Date.now()) {
  if (isExpired(policy, nowMs)) {
    return { mode: 'audit', policy_expired: true };
  }
  return { mode: policy.mode, policy_expired: false };
}

module.exports = {
  DEV_PUBLIC_KEY_HEX,
  serializeUnsigned,
  parseAndVerify,
  isExpired,
  effectiveMode,
};
