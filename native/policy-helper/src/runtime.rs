use crate::policy::restore_last_good;
use crate::policy_store::PolicyStore;
use crate::state::{now_unix_ms, HelperState};
use crate::DEV_PUBLIC_KEY_HEX;
use std::path::PathBuf;
use std::time::Duration;

pub struct HelperArgs {
    pub store_dir: PathBuf,
    pub pipe_name: String,
    pub public_key_hex: String,
    pub as_service: bool,
}

pub fn default_service_store() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("VMG").join("Sentinel").join("policy-helper")
}

pub fn parse_args(as_service: bool) -> HelperArgs {
    let mut store_dir = if as_service {
        default_service_store()
    } else {
        PathBuf::from(".policy-helper-state")
    };
    let mut pipe_name = "vmg-sentinel-helper".to_string();
    let mut public_key_hex = DEV_PUBLIC_KEY_HEX.to_string();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--store-dir" => {
                if let Some(value) = iter.next() {
                    store_dir = PathBuf::from(value);
                }
            }
            "--pipe-name" => {
                if let Some(value) = iter.next() {
                    pipe_name = value;
                }
            }
            "--pubkey" => {
                if let Some(path) = iter.next() {
                    if let Ok(raw) = std::fs::read_to_string(path) {
                        public_key_hex = raw.trim().to_string();
                    }
                }
            }
            "--service" | "--install" | "--uninstall" => {}
            _ => {}
        }
    }
    HelperArgs {
        store_dir,
        pipe_name,
        public_key_hex,
        as_service,
    }
}

pub async fn run_helper(
    args: HelperArgs,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = PolicyStore::new(args.store_dir.clone());
    store.ensure_dir()?;

    let last_good = match store.load_last_good()? {
        Some(doc) => match restore_last_good(doc, &args.public_key_hex) {
            Ok(restored) => Some(restored),
            Err(error) => {
                eprintln!("policy-helper: ignoring tampered last-good policy: {error}");
                None
            }
        },
        None => None,
    };

    #[cfg(windows)]
    {
        let leftover: Vec<String> = last_good
            .as_ref()
            .map(|doc| doc.sites.deny.clone())
            .unwrap_or_default()
            .into_iter()
            .chain([
                "facebook.com".into(),
                "youtube.com".into(),
                "instagram.com".into(),
                "tiktok.com".into(),
                "reddit.com".into(),
                "redditstatic.com".into(),
                "redditmedia.com".into(),
                "redd.it".into(),
                "twitter.com".into(),
                "x.com".into(),
            ])
            .collect();
        crate::enforce::firewall::remove_named_sites(leftover);
    }

    eprintln!(
        "vmg-sentinel-helper starting build={} name={} store={} service={} privilege={}",
        crate::HELPER_BUILD,
        args.pipe_name,
        args.store_dir.display(),
        args.as_service,
        crate::privilege::current()
    );

    let state = HelperState::new(
        store,
        args.public_key_hex,
        last_good,
        args.as_service,
    );
    let heartbeat_state = std::sync::Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            *heartbeat_state.heartbeat_unix_ms.lock().await = now_unix_ms();
        }
    });
    let refresh_state = std::sync::Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(45)).await;
            if *refresh_state.session_active.lock().await {
                refresh_state.reconcile().await;
            }
        }
    });

    tokio::select! {
        result = crate::ipc::listen(args.pipe_name, state) => result?,
        _ = shutdown => {}
    }
    let _ = crate::enforce::clear_enforcement();
    Ok(())
}
