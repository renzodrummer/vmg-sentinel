import { createPrivateKey, sign } from 'node:crypto';
import {
  DEV_PUBLIC_KEY_HEX,
  parseAndVerify,
  serializeUnsigned,
  effectiveMode,
} from './policy-document.js';

const DEV_SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

function privateKeyFromSeed(seedHex) {
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(seedHex, 'hex'),
  ]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function makeUnsigned(overrides = {}) {
  return {
    version: 1,
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    ttl_seconds: 3600,
    mode: 'audit',
    sites: { allow: [], deny: ['facebook.com'] },
    apps: { deny: [{ kind: 'publisher', value: 'O=Discord Inc.' }] },
    ...overrides,
  };
}

function signDoc(unsigned) {
  const key = privateKeyFromSeed(DEV_SEED_HEX);
  const signature = sign(null, serializeUnsigned(unsigned), key).toString('hex');
  return { ...unsigned, signature };
}

describe('policy-document', () => {
  it('parses a signed unexpired policy and seeds the allowlist', () => {
    const result = parseAndVerify(signDoc(makeUnsigned()), DEV_PUBLIC_KEY_HEX);
    expect(result.ok).toBe(true);
    expect(result.policy.sites.allow).toContain('login.microsoftonline.com');
    expect(result.policy.sites.allow).toContain('login.windows.net');
    expect(result.policy.sites.allow).toContain('teams.microsoft.com');
    expect(result.policy.mode).toBe('audit');
  });

  it('rejects unsigned', () => {
    const result = parseAndVerify(makeUnsigned({ signature: '' }));
    expect(result).toEqual({ ok: false, code: 'POLICY_UNSIGNED' });
  });

  it('rejects expired', () => {
    const issued = new Date(Date.now() - 7200_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const result = parseAndVerify(signDoc(makeUnsigned({ issued_at: issued, ttl_seconds: 3600 })));
    expect(result).toEqual({ ok: false, code: 'POLICY_EXPIRED' });
  });

  it('keeps audit vs block as a mode flag', () => {
    const audit = parseAndVerify(signDoc(makeUnsigned({ mode: 'audit' })));
    const block = parseAndVerify(signDoc(makeUnsigned({ mode: 'block' })));
    expect(audit.policy.mode).toBe('audit');
    expect(block.policy.mode).toBe('block');
  });

  it('downgrades expired last-good to audit without unlocking the document', () => {
    const policy = signDoc(
      makeUnsigned({
        issued_at: '2020-01-01T00:00:00Z',
        ttl_seconds: 60,
        mode: 'block',
      }),
    );
    const ttl = effectiveMode(policy, Date.parse('2020-01-01T00:02:00Z'));
    expect(ttl).toEqual({ mode: 'audit', policy_expired: true });
  });
});
