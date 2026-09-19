//! Detect Windows Defender Application Control / App Control for Business.
//! This helper never deploys a WDAC policy — an allow-only or unsigned XML can
//! brick the device. Enforce belongs to Intune/MDE after an audit ring.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WdacStatus {
    pub present: bool,
    pub audit_mode: bool,
}

impl WdacStatus {
    pub fn absent() -> Self {
        Self {
            present: false,
            audit_mode: false,
        }
    }
}

pub fn detect() -> WdacStatus {
    #[cfg(windows)]
    {
        windows_detect()
    }
    #[cfg(not(windows))]
    {
        WdacStatus::absent()
    }
}

/// Intentionally not implemented. Callers must not ship a CiTool deploy from here.
pub fn deploy_deny_list(_xml: &str) -> Result<(), &'static str> {
    Err("WDAC deploy is not implemented; use Intune/MDE audit-first, never from this helper")
}

#[cfg(windows)]
fn windows_detect() -> WdacStatus {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let umci = dword(
        &hklm,
        r"SYSTEM\CurrentControlSet\Control\CI",
        "UMCIEnabled",
    );
    let umci_audit = dword(
        &hklm,
        r"SYSTEM\CurrentControlSet\Control\CI",
        "UMCIAuditMode",
    );
    let device_guard = dword(
        &hklm,
        r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
        "ConfigCIPolicyEnable",
    )
    .or_else(|| {
        dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        )
    });
    let present = umci == Some(1) || device_guard == Some(1);
    WdacStatus {
        present,
        audit_mode: present && umci_audit.unwrap_or(0) == 1,
    }
}

#[cfg(windows)]
fn dword(hklm: &winreg::RegKey, path: &str, name: &str) -> Option<u32> {
    hklm.open_subkey(path)
        .ok()
        .and_then(|key| key.get_value(name).ok())
}

#[cfg(test)]
mod tests {
    use super::deploy_deny_list;

    #[test]
    fn never_deploys_wdac_xml() {
        assert!(deploy_deny_list("<SiPolicy/>").is_err());
    }
}
