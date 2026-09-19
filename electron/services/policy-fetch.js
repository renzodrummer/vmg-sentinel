const { parseAndVerify } = require('./policy-document');

const DEFAULT_PATH = '/v1/agent/endpoint-policy';

function policyUrl(apiUrl, path = DEFAULT_PATH) {
  const base = String(apiUrl || '').replace(/\/$/, '');
  const suffix = path.startsWith('/') ? path : `/${path}`;
  return `${base}${suffix}`;
}

async function fetchCitadelPolicy({
  apiUrl,
  cookieHeader,
  path = DEFAULT_PATH,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!apiUrl) {
    return { ok: false, code: 'POLICY_FETCH_FAILED', message: 'missing api url' };
  }
  if (typeof fetchImpl !== 'function') {
    return { ok: false, code: 'POLICY_FETCH_FAILED', message: 'fetch unavailable' };
  }

  let response;
  try {
    response = await fetchImpl(policyUrl(apiUrl, path), {
      method: 'GET',
      headers: cookieHeader ? { Cookie: cookieHeader } : {},
    });
  } catch (error) {
    return {
      ok: false,
      code: 'POLICY_FETCH_FAILED',
      message: error?.message || 'network error',
    };
  }

  if (response.status === 404) {
    return { ok: false, code: 'POLICY_NOT_FOUND' };
  }
  if (!response.ok) {
    return { ok: false, code: 'POLICY_FETCH_FAILED', status: response.status };
  }

  let document;
  try {
    document = await response.json();
  } catch {
    return { ok: false, code: 'POLICY_INVALID' };
  }

  const verified = parseAndVerify(document);
  if (!verified.ok) {
    return verified;
  }
  return { ok: true, policy: verified.policy };
}

module.exports = { fetchCitadelPolicy, policyUrl, DEFAULT_PATH };
