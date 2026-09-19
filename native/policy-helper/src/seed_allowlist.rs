/// SSO, Citadel/Sentinel APIs, Microsoft 365, and OS update hosts. Always merged into sites.allow.
/// Keep this list deny-list-safe: never a broad `*.microsoft.com`.
pub const SEED_SITE_ALLOW: &[&str] = &[
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.windows.net",
    "login.live.com",
    "login.microsoftonline.us",
    "citadel-api.vmg-portal.com",
    "citadel-api-dev.vmg-portal.com",
    "citadel-api-local.vmg-portal.com",
    "admin-api.vmg-portal.com",
    "admin-api-dev.vmg-portal.com",
    "admin-api-local.vmg-portal.com",
    "office.com",
    "www.office.com",
    "outlook.office.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "onedrive.live.com",
    "graph.microsoft.com",
    "officecdn.microsoft.com",
    "config.office.com",
    "nexus.officeapps.live.com",
    "activation.sls.microsoft.com",
    "crl.microsoft.com",
    "update.microsoft.com",
    "windowsupdate.microsoft.com",
    "dns.msftncsi.com",
    "www.msftconnecttest.com",
    "time.windows.com",
    "swscan.apple.com",
    "swcdn.apple.com",
    "gdmf.apple.com",
    "mesu.apple.com",
];

pub fn merge_site_allow(existing: &[String]) -> Vec<String> {
    let mut out: Vec<String> = SEED_SITE_ALLOW.iter().map(|s| (*s).to_string()).collect();
    for host in existing {
        if !out.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            out.push(host.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{merge_site_allow, SEED_SITE_ALLOW};

    #[test]
    fn seed_keeps_sso_and_office() {
        assert!(SEED_SITE_ALLOW.contains(&"login.windows.net"));
        assert!(SEED_SITE_ALLOW.contains(&"teams.microsoft.com"));
        assert!(SEED_SITE_ALLOW.contains(&"login.microsoftonline.com"));
        let merged = merge_site_allow(&["custom.example".into()]);
        assert!(merged.iter().any(|h| h == "custom.example"));
        assert!(merged.iter().any(|h| h == "graph.microsoft.com"));
    }
}
