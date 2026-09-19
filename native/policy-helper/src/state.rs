use crate::enforce::plan::{AuditEvent, EnforcePlan};
use crate::enforce::{apply_plan, clear_enforcement, EnforceReport};
use crate::policy::{PolicyDocument, PolicyMode};
use crate::policy_store::PolicyStore;
use crate::ttl::{effective_mode, expires_at, format_rfc3339};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct HelperState {
    pub store: PolicyStore,
    pub public_key_hex: String,
    pub running_as_service: bool,
    pub heartbeat_unix_ms: Mutex<u64>,
    pub last_good: Mutex<Option<PolicyDocument>>,
    pub session_active: Mutex<bool>,
    pub session_reason: Mutex<String>,
    pub recent_blocks: Mutex<Vec<AuditEvent>>,
    pub last_report: Mutex<EnforceReport>,
}

impl HelperState {
    pub fn new(
        store: PolicyStore,
        public_key_hex: String,
        last_good: Option<PolicyDocument>,
        running_as_service: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            public_key_hex,
            running_as_service,
            heartbeat_unix_ms: Mutex::new(now_unix_ms()),
            last_good: Mutex::new(last_good),
            session_active: Mutex::new(false),
            session_reason: Mutex::new("idle".into()),
            recent_blocks: Mutex::new(Vec::new()),
            last_report: Mutex::new(EnforceReport::default()),
        })
    }

    pub async fn set_session(&self, active: bool, reason: &str) {
        *self.session_active.lock().await = active;
        *self.session_reason.lock().await = reason.to_string();
        self.reconcile().await;
    }

    pub async fn reconcile(&self) {
        let session_active = *self.session_active.lock().await;
        let last = self.last_good.lock().await.clone();
        let now = time::OffsetDateTime::now_utc();
        let report = tokio::task::spawn_blocking(move || {
            if let Some(doc) = last {
                let plan = EnforcePlan::from_policy(&doc, session_active, now);
                apply_plan(&plan)
            } else {
                clear_enforcement()
            }
        })
        .await
        .unwrap_or_else(|error| EnforceReport {
            last_error: Some(format!("enforce task: {error}")),
            ..EnforceReport::default()
        });
        {
            let mut recent = self.recent_blocks.lock().await;
            recent.extend(report.events.iter().cloned());
            let extra = recent.len().saturating_sub(50);
            if extra > 0 {
                recent.drain(0..extra);
            }
        }
        *self.last_report.lock().await = report;
    }

    pub async fn status_json(&self) -> Value {
        let now = time::OffsetDateTime::now_utc();
        let heartbeat = *self.heartbeat_unix_ms.lock().await;
        let last = self.last_good.lock().await.clone();
        let session_active = *self.session_active.lock().await;
        let session_reason = self.session_reason.lock().await.clone();
        let report = self.last_report.lock().await.clone();
        let platform = current_platform();
        let privilege = crate::privilege::current();
        let common = json!({
            "helper_pid": std::process::id(),
            "helper_build": crate::HELPER_BUILD,
            "heartbeat_unix_ms": heartbeat,
            "platform": platform,
            "privilege": privilege,
            "running_as_service": self.running_as_service,
            "needs_service": report.needs_service || privilege == "user",
            "session_active": session_active,
            "session_reason": session_reason,
            "enforcing": report.enforcing,
            "needs_admin": report.needs_admin,
            "filters_added": report.filters_added,
            "apps_reconciled": report.apps_reconciled,
            "enforcement": report.layer,
            "engine": report.engine,
            "app_engine": report.app_engine,
            "mde_present": report.mde_present,
            "mde_network_protection": report.mde_network_protection,
            "wdac_present": report.wdac_present,
            "wdac_audit_mode": report.wdac_audit_mode,
            "ip_fallback": report.ip_fallback,
            "terminate_enabled": report.terminate_enabled,
            "last_error": report.last_error,
        });
        if let Some(doc) = last {
            let (mode, expired) = effective_mode(&doc, now);
            let mut value = common;
            value["policy_loaded"] = json!(true);
            value["policy_version"] = json!(doc.version);
            value["policy_mode"] = json!(match mode {
                PolicyMode::Audit => "audit",
                PolicyMode::Block => "block",
            });
            value["policy_expired"] = json!(expired);
            value["policy_expires_at"] = json!(expires_at(&doc).ok().map(format_rfc3339));
            value
        } else {
            let mut value = common;
            value["policy_loaded"] = json!(false);
            value["policy_version"] = json!(null);
            value["policy_mode"] = json!(null);
            value["policy_expired"] = json!(false);
            value["policy_expires_at"] = json!(null);
            value["enforcing"] = json!(false);
            value["filters_added"] = json!(0);
            value["apps_reconciled"] = json!(0);
            value
        }
    }

    pub async fn recent_blocks(&self) -> Vec<AuditEvent> {
        self.recent_blocks.lock().await.clone()
    }
}

pub fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unsupported"
    }
}
