const SEED_SITE_ALLOW = [
  'login.microsoftonline.com',
  'login.microsoft.com',
  'login.windows.net',
  'login.live.com',
  'login.microsoftonline.us',
  'citadel-api.vmg-portal.com',
  'citadel-api-dev.vmg-portal.com',
  'citadel-api-local.vmg-portal.com',
  'admin-api.vmg-portal.com',
  'admin-api-dev.vmg-portal.com',
  'admin-api-local.vmg-portal.com',
  'office.com',
  'www.office.com',
  'outlook.office.com',
  'outlook.office365.com',
  'teams.microsoft.com',
  'onedrive.live.com',
  'graph.microsoft.com',
  'officecdn.microsoft.com',
  'config.office.com',
  'nexus.officeapps.live.com',
  'activation.sls.microsoft.com',
  'crl.microsoft.com',
  'update.microsoft.com',
  'windowsupdate.microsoft.com',
  'dns.msftncsi.com',
  'www.msftconnecttest.com',
  'time.windows.com',
  'swscan.apple.com',
  'swcdn.apple.com',
  'gdmf.apple.com',
  'mesu.apple.com',
];

function mergeSiteAllow(existing = []) {
  const out = [...SEED_SITE_ALLOW];
  for (const host of existing) {
    if (!out.some((h) => h.toLowerCase() === String(host).toLowerCase())) {
      out.push(host);
    }
  }
  return out;
}

module.exports = { SEED_SITE_ALLOW, mergeSiteAllow };
