use vmg_sentinel_helper::auth::{authorize, PeerIdentity};
use vmg_sentinel_helper::ipc::protocol::{IpcError, IpcMethod, PIPE_SDDL};

#[test]
fn unauthenticated_local_peer_cannot_apply_policy() {
    let peer = PeerIdentity::unauthenticated();
    assert_eq!(
        authorize(IpcMethod::ApplyPolicy, &peer),
        Err(IpcError::Unauthenticated)
    );
    assert_eq!(
        authorize(IpcMethod::GetStatus, &peer),
        Err(IpcError::Unauthenticated)
    );
}

#[test]
fn authenticated_peer_can_get_status() {
    let peer = PeerIdentity {
        authenticated: true,
        anonymous: false,
        process_id: 42,
    };
    assert!(authorize(IpcMethod::GetStatus, &peer).is_ok());
    assert!(authorize(IpcMethod::ApplyPolicy, &peer).is_ok());
    assert!(authorize(IpcMethod::SetSession, &peer).is_ok());
}

#[test]
fn run_command_never_authorized() {
    let peer = PeerIdentity {
        authenticated: true,
        anonymous: false,
        process_id: 42,
    };
    assert_eq!(
        authorize(IpcMethod::Forbidden, &peer),
        Err(IpcError::Forbidden)
    );
}

#[test]
fn pipe_sddl_denies_anonymous() {
    assert!(PIPE_SDDL.contains("(D;;GA;;;AN)"));
}
