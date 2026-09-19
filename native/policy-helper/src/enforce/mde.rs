//! Detect Microsoft Defender / MDE. Sentinel must not duplicate web filters when
//! Defender Network Protection is already on.

use crate::enforce::safety::NetworkProtection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdeStatus {
    pub present: bool,
    pub network_protection: NetworkProtection,
}

impl MdeStatus {
    pub fn absent() -> Self {
        Self {
            present: false,
            network_protection: NetworkProtection::Unknown,
        }
    }
}

pub fn detect() -> MdeStatus {
    #[cfg(windows)]
    {
        windows_detect()
    }
    #[cfg(not(windows))]
    {
        MdeStatus::absent()
    }
}

#[cfg(windows)]
fn windows_detect() -> MdeStatus {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let present = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Windows Defender")
        .is_ok()
        || service_hint_present();

    let network_protection = read_network_protection(&hklm);
    MdeStatus {
        present: present || network_protection.is_on(),
        network_protection,
    }
}

#[cfg(windows)]
fn read_network_protection(hklm: &winreg::RegKey) -> NetworkProtection {
    const KEYS: &[&str] = &[
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
        r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
    ];
    for key in KEYS {
        if let Ok(sub) = hklm.open_subkey(key) {
            if let Ok(value) = sub.get_value::<u32, _>("EnableNetworkProtection") {
                return match value {
                    0 => NetworkProtection::Off,
                    1 => NetworkProtection::Block,
                    2 => NetworkProtection::Audit,
                    _ => NetworkProtection::Unknown,
                };
            }
        }
    }
    NetworkProtection::Unknown
}

#[cfg(windows)]
fn service_hint_present() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\WinDefend")
        .is_ok()
}
