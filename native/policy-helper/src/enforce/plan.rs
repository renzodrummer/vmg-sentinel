use crate::policy::{AppDenyRule, PolicyDocument, PolicyMode};
use crate::ttl::effective_mode;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub policy_version: u64,
    pub rule_id: String,
    pub actor: String,
    pub process_path: String,
    pub hostname: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct EnforcePlan {
    pub policy_version: u64,
    pub mode: PolicyMode,
    pub session_active: bool,
    pub expired: bool,
    pub sites_deny: Vec<String>,
    pub apps_deny: Vec<AppDenyRule>,
}

impl EnforcePlan {
    pub fn from_policy(doc: &PolicyDocument, session_active: bool, now: time::OffsetDateTime) -> Self {
        let (mode, expired) = effective_mode(doc, now);
        Self {
            policy_version: doc.version,
            mode,
            session_active,
            expired,
            sites_deny: doc.sites.deny.clone(),
            apps_deny: doc.apps.deny.clone(),
        }
    }

    pub fn should_block(&self) -> bool {
        self.session_active && !self.expired && self.mode == PolicyMode::Block
    }

    pub fn should_audit(&self) -> bool {
        self.session_active && !self.expired && self.mode == PolicyMode::Audit
    }
}

/// Stable identity of the signed deny lists + session gate. Ignores issued_at / signature
/// so a re-signed copy of the same lists does not force AppLocker PowerShell.
pub fn plan_fingerprint(plan: &EnforcePlan) -> String {
    let mut sites: Vec<String> = plan
        .sites_deny
        .iter()
        .map(|site| site.to_ascii_lowercase())
        .collect();
    sites.sort();
    sites.dedup();
    let mut apps: Vec<String> = plan
        .apps_deny
        .iter()
        .map(|rule| {
            format!(
                "{:?}:{}:{}",
                rule.kind,
                rule.alg.as_deref().unwrap_or(""),
                rule.value.to_ascii_lowercase()
            )
        })
        .collect();
    apps.sort();
    format!(
        "block={}|audit={}|sites={}|apps={}",
        plan.should_block(),
        plan.should_audit(),
        sites.join(","),
        apps.join(",")
    )
}

pub fn ips_fingerprint(resolved: &[(String, IpAddr)]) -> String {
    let mut rows: Vec<String> = resolved
        .iter()
        .map(|(host, ip)| format!("{}|{ip}", host.to_ascii_lowercase()))
        .collect();
    rows.sort();
    rows.join(";")
}

pub fn paths_fingerprint(paths: &[String]) -> String {
    let mut rows: Vec<String> = paths.iter().map(|path| path.to_ascii_lowercase()).collect();
    rows.sort();
    rows.join(";")
}

pub fn host_matches_deny(hostname: &str, pattern: &str) -> bool {
    let host = hostname.trim_end_matches('.').to_ascii_lowercase();
    let needle = pattern.trim_end_matches('.').to_ascii_lowercase();
    host == needle || host.ends_with(&format!(".{needle}"))
}

pub fn ipv4_wfp_host_order(octets: [u8; 4]) -> u32 {
    // WFP documents FWP_UINT32 IPv4 as host byte order. 1.2.3.4 → 0x01020304.
    u32::from_be_bytes(octets)
}

pub fn resolve_deny_hosts(patterns: &[String]) -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pattern in patterns {
        let mut names = vec![pattern.clone()];
        for prefix in ["www.", "m.", "old.", "i.", "v.", "preview."] {
            if !pattern.starts_with(prefix) {
                names.push(format!("{prefix}{pattern}"));
            }
        }
        for name in names {
            if let Ok(addrs) = (name.as_str(), 0u16).to_socket_addrs_or_empty() {
                for addr in addrs {
                    let ip = addr.ip();
                    if seen.insert((pattern.clone(), ip)) {
                        eprintln!("policy-helper: resolve {name} -> {ip}");
                        out.push((pattern.clone(), ip));
                    }
                }
            }
        }
    }
    out
}

trait ToSocketAddrsOrEmpty {
    fn to_socket_addrs_or_empty(self) -> std::io::Result<Vec<std::net::SocketAddr>>;
}

impl ToSocketAddrsOrEmpty for (&str, u16) {
    fn to_socket_addrs_or_empty(self) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        match self.to_socket_addrs() {
            Ok(iter) => Ok(iter.collect()),
            Err(error) => {
                eprintln!("policy-helper: DNS lookup failed for {}: {error}", self.0);
                Ok(vec![])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_suffix_match() {
        assert!(host_matches_deny("www.facebook.com", "facebook.com"));
        assert!(host_matches_deny("facebook.com", "facebook.com"));
        assert!(!host_matches_deny("notfacebook.com", "facebook.com"));
    }

    #[test]
    fn ipv4_wfp_uses_host_order() {
        assert_eq!(ipv4_wfp_host_order([1, 2, 3, 4]), 0x0102_0304);
    }

    #[test]
    fn block_only_when_session_and_block_mode() {
        let plan = EnforcePlan {
            policy_version: 1,
            mode: PolicyMode::Block,
            session_active: true,
            expired: false,
            sites_deny: vec![],
            apps_deny: vec![],
        };
        assert!(plan.should_block());
        let mut idle = plan.clone();
        idle.session_active = false;
        assert!(!idle.should_block());
        let mut audit = plan;
        audit.mode = PolicyMode::Audit;
        assert!(!audit.should_block());
        assert!(audit.should_audit());
    }

    #[test]
    fn plan_fingerprint_ignores_policy_version() {
        let mut plan = EnforcePlan {
            policy_version: 1,
            mode: PolicyMode::Block,
            session_active: true,
            expired: false,
            sites_deny: vec!["Reddit.com".into(), "youtube.com".into()],
            apps_deny: vec![],
        };
        let first = plan_fingerprint(&plan);
        plan.policy_version = 9;
        assert_eq!(first, plan_fingerprint(&plan));
        plan.session_active = false;
        assert_ne!(first, plan_fingerprint(&plan));
    }

    #[test]
    fn ips_fingerprint_is_order_independent() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(1, 2, 3, 4);
        let b = Ipv4Addr::new(5, 6, 7, 8);
        let left = ips_fingerprint(&[("Host".into(), a.into()), ("host".into(), b.into())]);
        let right = ips_fingerprint(&[("host".into(), b.into()), ("host".into(), a.into())]);
        assert_eq!(left, right);
    }
}
