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
}
