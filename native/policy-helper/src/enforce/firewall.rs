//! Session-gated outbound blocks via Windows Defender Firewall (INetFwPolicy2).
//! These rules apply to every app, including Chrome and curl, and are removed
//! when tracking stops or the helper exits.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use windows::core::BSTR;
use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE_TYPE2, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};

const GROUP: &str = "VMG Sentinel";
static ADDED_RULES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static FIREWALL_WAS_OFF: Mutex<Vec<i32>> = Mutex::new(Vec::new());

fn active_profiles(policy: &INetFwPolicy2) -> Result<Vec<NET_FW_PROFILE_TYPE2>, String> {
    let mask = unsafe { policy.CurrentProfileTypes() }
        .map_err(|error| format!("CurrentProfileTypes: {error}"))?;
    Ok([
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC,
    ]
    .into_iter()
    .filter(|profile| mask & profile.0 != 0)
    .collect())
}

fn ensure_firewall_on() -> Result<(), String> {
    let policy = policy()?;
    let profiles = active_profiles(&policy)?;
    if profiles.is_empty() {
        return Err("Windows Firewall has no active profile".into());
    }
    let mut turned_on = FIREWALL_WAS_OFF.lock().map_err(|_| "firewall lock")?;
    turned_on.clear();
    for profile in profiles {
        let enabled = unsafe { policy.get_FirewallEnabled(profile) }
            .map_err(|error| format!("FirewallEnabled: {error}"))?;
        if enabled.as_bool() {
            continue;
        }
        unsafe { policy.put_FirewallEnabled(profile, VARIANT_TRUE) }.map_err(|error| {
            format!(
                "Windows Firewall is off and could not be enabled ({error}). Turn on Windows Defender Firewall, then Start Tracking again."
            )
        })?;
        eprintln!(
            "policy-helper: enabled Windows Firewall for profile {}",
            profile.0
        );
        turned_on.push(profile.0);
    }
    Ok(())
}

fn restore_firewall() {
    let Ok(policy) = policy() else {
        return;
    };
    let Ok(mut turned_on) = FIREWALL_WAS_OFF.lock() else {
        return;
    };
    for profile in turned_on.drain(..) {
        let _ = unsafe {
            policy.put_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile), VARIANT_FALSE)
        };
        eprintln!("policy-helper: restored Windows Firewall off for profile {profile}");
    }
}

fn ensure_com() {
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
}

fn policy() -> Result<INetFwPolicy2, String> {
    ensure_com();
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
        .map_err(|error| format!("INetFwPolicy2: {error}"))
}

fn rule_name(kind: &str, value: &str) -> String {
    format!("{GROUP} {kind} {value}")
}

pub fn apply_sites(resolved: &[(String, IpAddr)]) -> Result<u32, String> {
    if resolved.is_empty() {
        return Ok(0);
    }
    ensure_firewall_on()?;
    let mut by_host: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    for (host, ip) in resolved {
        let entry = by_host.entry(host.clone()).or_default();
        match ip {
            IpAddr::V4(v4) => entry.0.push(v4.to_string()),
            IpAddr::V6(v6) => entry.1.push(v6.to_string()),
        }
    }
    let rules = unsafe { policy()?.Rules() }.map_err(|error| format!("Rules: {error}"))?;
    let mut added = 0u32;
    let mut names = ADDED_RULES.lock().map_err(|_| "rules lock")?;
    for (host, (v4, v6)) in by_host {
        if !v4.is_empty() {
            let name = rule_name("site", &host);
            add_rule(&rules, &name, Some(&v4.join(",")), None)?;
            eprintln!(
                "policy-helper: firewall block site {host} ({})",
                v4.join(", ")
            );
            names.push(name);
            added += 1;
        }
        if !v6.is_empty() {
            let name = rule_name("site", &format!("{host} v6"));
            add_rule(&rules, &name, Some(&v6.join(",")), None)?;
            eprintln!(
                "policy-helper: firewall block site {host} v6 ({})",
                v6.join(", ")
            );
            names.push(name);
            added += 1;
        }
    }
    Ok(added)
}

pub fn apply_apps(paths: &[String]) -> Result<u32, String> {
    if paths.is_empty() {
        return Ok(0);
    }
    ensure_firewall_on()?;
    let rules = unsafe { policy()?.Rules() }.map_err(|error| format!("Rules: {error}"))?;
    let mut added = 0u32;
    let mut seen = HashSet::new();
    let mut names = ADDED_RULES.lock().map_err(|_| "rules lock")?;
    for path in paths {
        if !seen.insert(path.to_ascii_lowercase()) {
            continue;
        }
        let name = rule_name("app", path);
        add_rule(&rules, &name, None, Some(path))?;
        eprintln!("policy-helper: firewall block app {path}");
        names.push(name);
        added += 1;
    }
    Ok(added)
}

pub fn clear() -> Result<(), String> {
    let names = {
        let mut guard = ADDED_RULES.lock().map_err(|_| "rules lock")?;
        guard.drain(..).collect::<Vec<_>>()
    };
    if names.is_empty() {
        return Ok(());
    }
    let Ok(policy) = policy() else {
        return Ok(());
    };
    let Ok(rules) = (unsafe { policy.Rules() }) else {
        return Ok(());
    };
    for name in names {
        let _ = unsafe { rules.Remove(&BSTR::from(name.as_str())) };
        eprintln!("policy-helper: firewall removed {name}");
    }
    restore_firewall();
    Ok(())
}

pub fn remove_named_sites(hosts: impl IntoIterator<Item = impl AsRef<str>>) {
    let Ok(policy) = policy() else {
        return;
    };
    let Ok(rules) = (unsafe { policy.Rules() }) else {
        return;
    };
    for host in hosts {
        let host = host.as_ref();
        let name = rule_name("site", host);
        let v6 = rule_name("site", &format!("{host} v6"));
        let _ = unsafe { rules.Remove(&BSTR::from(name.as_str())) };
        let _ = unsafe { rules.Remove(&BSTR::from(v6.as_str())) };
    }
}

fn add_rule(
    rules: &INetFwRules,
    name: &str,
    remote_addrs: Option<&str>,
    app_path: Option<&str>,
) -> Result<(), String> {
    let _ = unsafe { rules.Remove(&BSTR::from(name)) };
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_ALL) }
        .map_err(|error| format!("NetFwRule: {error}"))?;
    unsafe {
        rule.SetName(&BSTR::from(name))
            .map_err(|error| format!("SetName: {error}"))?;
        rule.SetGrouping(&BSTR::from(GROUP))
            .map_err(|error| format!("SetGrouping: {error}"))?;
        rule.SetDescription(&BSTR::from(
            "VMG Sentinel work-session block; removed when tracking stops",
        ))
        .map_err(|error| format!("SetDescription: {error}"))?;
        rule.SetDirection(NET_FW_RULE_DIR_OUT)
            .map_err(|error| format!("SetDirection: {error}"))?;
        rule.SetAction(NET_FW_ACTION_BLOCK)
            .map_err(|error| format!("SetAction: {error}"))?;
        rule.SetEnabled(VARIANT_TRUE)
            .map_err(|error| format!("SetEnabled: {error}"))?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0)
            .map_err(|error| format!("SetProfiles: {error}"))?;
        rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)
            .map_err(|error| format!("SetProtocol: {error}"))?;
        if let Some(addrs) = remote_addrs {
            rule.SetRemoteAddresses(&BSTR::from(addrs))
                .map_err(|error| format!("SetRemoteAddresses: {error}"))?;
        }
        if let Some(path) = app_path {
            rule.SetApplicationName(&BSTR::from(path))
                .map_err(|error| format!("SetApplicationName: {error}"))?;
        }
        rules
            .Add(&rule)
            .map_err(|error| format!("Add rule {name}: {error}"))?;
    }
    Ok(())
}
