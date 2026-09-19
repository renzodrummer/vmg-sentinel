use crate::auth::{authorize, PeerIdentity};
use crate::ipc::protocol::{err, ok, IpcError, IpcMethod, IpcRequest, IpcResponse};
use crate::policy::{parse_document, verify_and_normalize, PolicyDocument, PolicyError};
use crate::state::HelperState;
use serde_json::json;

pub async fn dispatch(payload: &[u8], peer: &PeerIdentity, state: &HelperState) -> IpcResponse {
    let req: IpcRequest = match serde_json::from_slice(payload) {
        Ok(value) => value,
        Err(_) => return err(0, IpcError::Internal("invalid request")),
    };
    let method = IpcMethod::parse(&req.method);
    if let Err(error) = authorize(method, peer) {
        return err(req.id, error);
    }
    match method {
        IpcMethod::GetStatus => ok(req.id, state.status_json().await),
        IpcMethod::GetRecentBlocks => {
            let events = state.recent_blocks().await;
            ok(req.id, json!({ "events": events }))
        }
        IpcMethod::SetSession => {
            let active = req
                .params
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let reason = req
                .params
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified");
            state.set_session(active, reason).await;
            ok(req.id, state.status_json().await)
        }
        IpcMethod::ReportTamper => {
            let kind = req
                .params
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let detail = req
                .params
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if state.store.append_tamper(kind, detail).is_err() {
                return err(req.id, IpcError::Internal("tamper log failed"));
            }
            ok(req.id, json!({ "recorded": true }))
        }
        IpcMethod::ApplyPolicy => match apply_policy(state, &req.params).await {
            Ok(doc) => ok(
                req.id,
                json!({
                    "version": doc.version,
                    "mode": doc.mode,
                }),
            ),
            Err(code) => err(req.id, IpcError::Policy(code)),
        },
        IpcMethod::Forbidden => err(req.id, IpcError::Forbidden),
    }
}

async fn apply_policy(
    state: &HelperState,
    params: &serde_json::Value,
) -> Result<PolicyDocument, &'static str> {
    let document = params.get("document").ok_or("POLICY_INVALID")?;
    let raw = serde_json::to_string(document).map_err(|_| "POLICY_INVALID")?;
    let parsed = parse_document(&raw).map_err(map_policy_error)?;
    let now = time::OffsetDateTime::now_utc();
    let normalized =
        verify_and_normalize(parsed, &state.public_key_hex, now).map_err(map_policy_error)?;
    state
        .store
        .save_last_good(&normalized)
        .map_err(|_| "INTERNAL")?;
    *state.last_good.lock().await = Some(normalized.clone());
    state.reconcile().await;
    Ok(normalized)
}

fn map_policy_error(error: PolicyError) -> &'static str {
    match error {
        PolicyError::Unsigned => "POLICY_UNSIGNED",
        PolicyError::Expired => "POLICY_EXPIRED",
        PolicyError::BadSignature => "POLICY_BAD_SIGNATURE",
        PolicyError::Invalid | PolicyError::InvalidAppRule => "POLICY_INVALID",
    }
}
