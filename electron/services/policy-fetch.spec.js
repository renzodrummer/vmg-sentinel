import { fetchCitadelPolicy, policyUrl } from './policy-fetch.js';

describe('policy-fetch', () => {
  it('builds the Citadel endpoint-policy URL', () => {
    expect(policyUrl('https://citadel-api-dev.vmg-portal.com/')).toBe(
      'https://citadel-api-dev.vmg-portal.com/v1/agent/endpoint-policy',
    );
  });

  it('returns POLICY_NOT_FOUND on 404 without applying unsigned JSON', async () => {
    const result = await fetchCitadelPolicy({
      apiUrl: 'https://citadel-api-dev.vmg-portal.com',
      fetchImpl: async () => ({ status: 404, ok: false, json: async () => ({}) }),
    });
    expect(result).toEqual({ ok: false, code: 'POLICY_NOT_FOUND' });
  });

  it('rejects an unsigned Citadel body', async () => {
    const result = await fetchCitadelPolicy({
      apiUrl: 'https://citadel-api-dev.vmg-portal.com',
      fetchImpl: async () => ({
        status: 200,
        ok: true,
        json: async () => ({
          version: 1,
          issued_at: '2026-01-01T00:00:00Z',
          ttl_seconds: 3600,
          mode: 'audit',
          sites: { allow: [], deny: [] },
          apps: { deny: [] },
        }),
      }),
    });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('POLICY_UNSIGNED');
  });
});
