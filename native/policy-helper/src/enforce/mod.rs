#[cfg(windows)]
pub mod applocker;
#[cfg(windows)]
pub mod firewall;
pub mod mde;
pub mod plan;
pub mod safety;
pub mod wdac;
#[cfg(windows)]
pub mod windows;

use crate::enforce::plan::{AuditEvent, EnforcePlan};
use crate::enforce::safety::{
    decide_app_engine, decide_site_engine, AppEngine, SafetySnapshot, SiteEngine,
};
use crate::policy::{AppDenyRule, AppMatchKind};

#[derive(Debug, Clone)]
pub struct EnforceReport {
    pub enforcing: bool,
    pub needs_admin: bool,
    pub needs_service: bool,
    pub filters_added: u32,
    pub apps_reconciled: u32,
    pub last_error: Option<String>,
    pub events: Vec<AuditEvent>,
    pub layer: &'static str,
    pub engine: &'static str,
    pub app_engine: &'static str,
    pub mde_present: bool,
    pub mde_network_protection: &'static str,
    pub wdac_present: bool,
    pub wdac_audit_mode: bool,
    pub ip_fallback: bool,
    pub terminate_enabled: bool,
}

impl Default for EnforceReport {
    fn default() -> Self {
        Self {
            enforcing: false,
            needs_admin: false,
            needs_service: false,
            filters_added: 0,
            apps_reconciled: 0,
            last_error: None,
            events: Vec::new(),
            layer: "idle",
            engine: "none",
            app_engine: "none",
            mde_present: false,
            mde_network_protection: "unknown",
            wdac_present: false,
            wdac_audit_mode: false,
            ip_fallback: false,
            terminate_enabled: false,
        }
    }
}

pub fn apply_plan(plan: &EnforcePlan) -> EnforceReport {
    let safety = SafetySnapshot::live();
    let site_engine = decide_site_engine(plan.should_block(), &safety);
    let app_engine = decide_app_engine(plan.should_block(), &safety);
    let mut report = EnforceReport {
        needs_service: crate::privilege::needs_service(),
        engine: site_engine.as_str(),
        app_engine: app_engine.as_str(),
        mde_present: safety.mde_present,
        mde_network_protection: safety.network_protection.as_str(),
        wdac_present: safety.wdac_present,
        wdac_audit_mode: safety.wdac_audit_mode,
        ip_fallback: site_engine == SiteEngine::IpFallback,
        terminate_enabled: app_engine == AppEngine::TerminateOptIn,
        layer: describe_layer(site_engine, app_engine),
        ..EnforceReport::default()
    };

    if !plan.should_block() && !plan.should_audit() {
        let _ = platform_clear();
        report.engine = "none";
        report.app_engine = "none";
        report.layer = describe_layer(SiteEngine::None, AppEngine::None);
        return report;
    }

    for hostname in &plan.sites_deny {
        report.events.push(AuditEvent {
            policy_version: plan.policy_version,
            rule_id: format!("site:{hostname}"),
            actor: "helper".into(),
            process_path: String::new(),
            hostname: hostname.clone(),
            action: if plan.should_block() {
                "would-block".into()
            } else {
                "audit".into()
            },
        });
    }

    let apply_wfp = site_engine == SiteEngine::IpFallback
        || app_engine == AppEngine::NetworkFilter
        || app_engine == AppEngine::LaunchDeny
        || app_engine == AppEngine::TerminateOptIn;
    if plan.should_audit() || !apply_wfp {
        let _ = platform_clear();
        if plan.should_block() {
            for rule in &plan.apps_deny {
                report.events.push(AuditEvent {
                    policy_version: plan.policy_version,
                    rule_id: format!("app:{}", rule.value),
                    actor: "helper".into(),
                    process_path: rule.value.clone(),
                    hostname: String::new(),
                    action: match app_engine {
                        AppEngine::DeferredToWdac => "deferred-wdac".into(),
                        _ => "would-block".into(),
                    },
                });
            }
        }
        report.enforcing = false;
        return report;
    }

    match platform_apply(plan, site_engine, app_engine) {
        Ok(mut applied) => {
            applied.events.splice(0..0, report.events);
            applied.enforcing = applied.filters_added > 0 || applied.apps_reconciled > 0;
            applied.engine = site_engine.as_str();
            applied.app_engine = app_engine.as_str();
            applied.mde_present = safety.mde_present;
            applied.mde_network_protection = safety.network_protection.as_str();
            applied.wdac_present = safety.wdac_present;
            applied.wdac_audit_mode = safety.wdac_audit_mode;
            applied.ip_fallback = site_engine == SiteEngine::IpFallback;
            applied.terminate_enabled = app_engine == AppEngine::TerminateOptIn;
            applied.needs_service = crate::privilege::needs_service();
            applied.layer = describe_layer(site_engine, app_engine);
            applied
        }
        Err(error) => {
            report.enforcing = false;
            report.needs_admin = error.contains("Access is denied") || error.contains("0x80070005");
            report.last_error = Some(error);
            report
        }
    }
}

pub fn clear_enforcement() -> EnforceReport {
    let safety = SafetySnapshot::live();
    let error = platform_clear().err();
    EnforceReport {
        last_error: error,
        needs_service: crate::privilege::needs_service(),
        engine: "none",
        app_engine: "none",
        mde_present: safety.mde_present,
        mde_network_protection: safety.network_protection.as_str(),
        wdac_present: safety.wdac_present,
        wdac_audit_mode: safety.wdac_audit_mode,
        layer: describe_layer(SiteEngine::None, AppEngine::None),
        ..EnforceReport::default()
    }
}

fn describe_layer(site: SiteEngine, app: AppEngine) -> &'static str {
    match (site, app) {
        (SiteEngine::IpFallback, _) => {
            "Windows Firewall outbound block of deny-list IPs (lifted when tracking stops)"
        }
        (_, AppEngine::LaunchDeny) => {
            "AppLocker exe deny plus close already-running deny apps (lifted when tracking stops)"
        }
        (_, AppEngine::NetworkFilter) => {
            "session WFP app-id network block (no process terminate)"
        }
        (_, AppEngine::TerminateOptIn) => {
            "opt-in one-shot terminate (not the default app engine)"
        }
        (SiteEngine::Audit, _) | (SiteEngine::None, AppEngine::Audit) => {
            "hostname audit only; no filters"
        }
        (SiteEngine::None, AppEngine::None) => "idle",
        (SiteEngine::DeferredToMde, _) => {
            "deferred to Microsoft Defender Network Protection"
        }
        (_, AppEngine::DeferredToWdac) => "deferred to WDAC / App Control",
    }
}

#[cfg(windows)]
fn platform_apply(
    plan: &EnforcePlan,
    site_engine: SiteEngine,
    app_engine: AppEngine,
) -> Result<EnforceReport, String> {
    crate::enforce::windows::apply(plan, site_engine, app_engine)
}

#[cfg(not(windows))]
fn platform_apply(
    plan: &EnforcePlan,
    _site_engine: SiteEngine,
    _app_engine: AppEngine,
) -> Result<EnforceReport, String> {
    let _ = plan;
    Err(
        "TODO(platform): macOS NEFilterDataProvider / ES_EVENT_TYPE_AUTH_EXEC; process terminate is not used"
            .into(),
    )
}

#[cfg(windows)]
fn platform_clear() -> Result<(), String> {
    crate::enforce::windows::clear()
}

#[cfg(not(windows))]
fn platform_clear() -> Result<(), String> {
    Ok(())
}

pub fn rule_matches_process(
    rule: &AppDenyRule,
    process_path: &str,
    sha256_hex: Option<&str>,
    publisher: Option<&str>,
) -> bool {
    match rule.kind {
        AppMatchKind::Path => {
            let needle = rule.value.to_ascii_lowercase();
            let path = process_path.replace('/', "\\").to_ascii_lowercase();
            path == needle
                || path.ends_with(&format!("\\{needle}"))
                || std::path::Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == needle)
        }
        AppMatchKind::Hash => sha256_hex
            .map(|hash| hash.eq_ignore_ascii_case(&rule.value))
            .unwrap_or(false),
        AppMatchKind::Publisher => publisher
            .map(|value| value.to_ascii_lowercase().contains(&rule.value.to_ascii_lowercase()))
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::rule_matches_process;
    use crate::policy::{AppDenyRule, AppMatchKind};

    #[test]
    fn path_rule_matches_file_name() {
        let rule = AppDenyRule {
            kind: AppMatchKind::Path,
            alg: None,
            value: "discord.exe".into(),
        };
        assert!(rule_matches_process(
            &rule,
            r"C:\Users\a\AppData\Local\Discord\Discord.exe",
            None,
            None
        ));
    }
}
