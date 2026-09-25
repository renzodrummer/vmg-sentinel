use vmg_sentinel_helper::runtime::{parse_args, run_helper};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let flags: Vec<String> = std::env::args().collect();
    #[cfg(windows)]
    {
        if flags.iter().any(|arg| arg == "--install") {
            return vmg_sentinel_helper::service::install();
        }
        if flags.iter().any(|arg| arg == "--uninstall") {
            return vmg_sentinel_helper::service::uninstall();
        }
        if flags.iter().any(|arg| arg == "--clear-blocks") {
            vmg_sentinel_helper::enforce::firewall::remove_all_sentinel_rules();
            vmg_sentinel_helper::enforce::applocker::clear();
            return Ok(());
        }
        if flags.iter().any(|arg| arg == "--service") {
            return vmg_sentinel_helper::service::dispatch();
        }
    }

    let args = parse_args(false);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_helper(args, async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}
