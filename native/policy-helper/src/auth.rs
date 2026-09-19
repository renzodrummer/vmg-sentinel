use crate::ipc::protocol::{IpcError, IpcMethod};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub authenticated: bool,
    pub anonymous: bool,
    pub process_id: u32,
}

impl PeerIdentity {
    pub fn unauthenticated() -> Self {
        Self {
            authenticated: false,
            anonymous: true,
            process_id: 0,
        }
    }
}

/// Typed IPC only. Unauthenticated local peers cannot apply policy.
pub fn authorize(method: IpcMethod, peer: &PeerIdentity) -> Result<(), IpcError> {
    if !peer.authenticated || peer.anonymous {
        return Err(IpcError::Unauthenticated);
    }
    match method {
        IpcMethod::ApplyPolicy
        | IpcMethod::GetStatus
        | IpcMethod::GetRecentBlocks
        | IpcMethod::ReportTamper
        | IpcMethod::SetSession => Ok(()),
        IpcMethod::Forbidden => Err(IpcError::Forbidden),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_cannot_apply_policy() {
        let peer = PeerIdentity::unauthenticated();
        assert_eq!(
            authorize(IpcMethod::ApplyPolicy, &peer),
            Err(IpcError::Unauthenticated)
        );
    }

    #[test]
    fn run_command_is_forbidden() {
        let peer = PeerIdentity {
            authenticated: true,
            anonymous: false,
            process_id: 1,
        };
        assert_eq!(
            authorize(IpcMethod::Forbidden, &peer),
            Err(IpcError::Forbidden)
        );
    }
}
