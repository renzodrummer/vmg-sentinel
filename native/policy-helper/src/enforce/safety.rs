//! Session-gated WFP is the product engine. Audit-only is opt-in.
//! Defender being installed does not skip filters: MDE is all-day policy, not Start Tracking.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtection {
    Off,
    Audit,
    Block,
    Unknown,
}

impl NetworkProtection {
    pub fn is_on(self) -> bool {
        matches!(self, Self::Audit | Self::Block)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteEngine {
    None,
    Audit,
    DeferredToMde,
    IpFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEngine {
    None,
    Audit,
    DeferredToWdac,
    LaunchDeny,
    NetworkFilter,
    TerminateOptIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetySnapshot {
    pub mde_present: bool,
    pub network_protection: NetworkProtection,
    pub wdac_present: bool,
    pub wdac_audit_mode: bool,
    pub audit_only: bool,
    pub terminate_opt_in: bool,
}

impl SafetySnapshot {
    pub fn live() -> Self {
        let mde = crate::enforce::mde::detect();
        let wdac = crate::enforce::wdac::detect();
        Self {
            mde_present: mde.present,
            network_protection: mde.network_protection,
            wdac_present: wdac.present,
            wdac_audit_mode: wdac.audit_mode,
            audit_only: env_flag("VMG_SENTINEL_AUDIT_ONLY"),
            terminate_opt_in: env_flag("VMG_SENTINEL_TERMINATE"),
        }
    }
}

pub fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

pub fn decide_site_engine(should_block: bool, safety: &SafetySnapshot) -> SiteEngine {
    if !should_block {
        return SiteEngine::None;
    }
    if safety.audit_only {
        return SiteEngine::Audit;
    }
    SiteEngine::IpFallback
}

pub fn decide_app_engine(should_block: bool, safety: &SafetySnapshot) -> AppEngine {
    if !should_block {
        return AppEngine::None;
    }
    if safety.audit_only {
        return AppEngine::Audit;
    }
    if safety.terminate_opt_in {
        return AppEngine::TerminateOptIn;
    }
    AppEngine::LaunchDeny
}

impl SiteEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Audit => "audit",
            Self::DeferredToMde => "mde",
            Self::IpFallback => "fw",
        }
    }
}

impl AppEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Audit => "audit",
            Self::DeferredToWdac => "wdac",
            Self::LaunchDeny => "launch",
            Self::NetworkFilter => "wfp_app",
            Self::TerminateOptIn => "terminate_opt_in",
        }
    }
}

impl NetworkProtection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Audit => "audit",
            Self::Block => "block",
            Self::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SafetySnapshot {
        SafetySnapshot {
            mde_present: false,
            network_protection: NetworkProtection::Off,
            wdac_present: false,
            wdac_audit_mode: false,
            audit_only: false,
            terminate_opt_in: false,
        }
    }

    #[test]
    fn block_mode_uses_session_wfp() {
        let safety = base();
        assert_eq!(decide_site_engine(true, &safety), SiteEngine::IpFallback);
        assert_eq!(decide_app_engine(true, &safety), AppEngine::LaunchDeny);
    }

    #[test]
    fn audit_only_env_skips_wfp() {
        let mut safety = base();
        safety.audit_only = true;
        assert_eq!(decide_site_engine(true, &safety), SiteEngine::Audit);
        assert_eq!(decide_app_engine(true, &safety), AppEngine::Audit);
    }

    #[test]
    fn defender_installed_does_not_skip_session_wfp() {
        let mut safety = base();
        safety.mde_present = true;
        safety.network_protection = NetworkProtection::Block;
        assert_eq!(decide_site_engine(true, &safety), SiteEngine::IpFallback);
    }

    #[test]
    fn idle_session_selects_none() {
        let safety = base();
        assert_eq!(decide_site_engine(false, &safety), SiteEngine::None);
        assert_eq!(decide_app_engine(false, &safety), AppEngine::None);
    }
}
