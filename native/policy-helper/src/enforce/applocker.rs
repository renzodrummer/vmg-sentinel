//! Session-gated AppLocker *Exe* deny rules. Listed apps cannot launch while
//! tracking is on. Rules are removed when tracking stops or the helper uninstalls.
//! This is not a WDAC CI policy and is not a taskkill loop.

use crate::policy::{AppDenyRule, AppMatchKind};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::Command;

const RULE_PREFIX: &str = "VMG Sentinel launch";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchTarget {
    Path(String),
    Hash(String),
    Publisher(String),
}

pub fn apply(rules: &[AppDenyRule]) -> Result<u32, String> {
    let targets = launch_targets(rules);
    if targets.is_empty() {
        return Ok(0);
    }
    clear();
    ensure_appid_service();
    let xml = exe_deny_xml(&targets);
    if !xml_is_safe_deny_list(&xml) {
        return Err(
            "refusing AppLocker apply: XML is missing the Everyone allow-all Exe rule or the packaged-app allow (deny-only policy would lock Settings / This PC Properties)".into(),
        );
    }
    let path = write_temp_xml(&xml)?;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Set-AppLockerPolicy -XmlPolicy '{}' -Merge; if (-not $?) {{ throw 'Set-AppLockerPolicy failed' }}",
                path.replace('\'', "''")
            ),
        ])
        .output()
        .map_err(|error| format!("AppLocker apply: {error}"))?;
    let _ = std::fs::remove_file(&path);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "AppLocker is not available or could not enable launch deny ({stderr}). Windows Home/Pro without AppLocker cannot refuse CreateProcess."
        ));
    }
    eprintln!(
        "policy-helper: AppLocker launch deny for {} rule(s)",
        targets.len()
    );
    Ok(targets.len() as u32)
}

pub fn clear() {
    let script = r#"
$ErrorActionPreference = 'Continue'
$tmp = Join-Path $env:TEMP ('vmg-sentinel-applocker-clear-' + [guid]::NewGuid().ToString() + '.xml')
try {
  $raw = Get-AppLockerPolicy -Local -Xml
} catch {
  $raw = $null
}
if ($raw) {
  try {
    $doc = [xml]$raw
    foreach ($collection in @($doc.AppLockerPolicy.RuleCollection)) {
      if (-not $collection) { continue }
      foreach ($node in @($collection.ChildNodes)) {
        $ruleName = $node.GetAttribute('Name')
        if ($ruleName -like 'VMG Sentinel *') {
          [void]$collection.RemoveChild($node)
        }
      }
      if ($collection.Type -eq 'Exe' -or $collection.Type -eq 'Appx') {
        $collection.SetAttribute('EnforcementMode', 'NotConfigured')
      }
    }
    $doc.Save($tmp)
    Set-AppLockerPolicy -XmlPolicy $tmp
  } catch {
    @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
'@ | Set-Content -Path $tmp -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $tmp
  }
} else {
  @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
'@ | Set-Content -Path $tmp -Encoding UTF8
  Set-AppLockerPolicy -XmlPolicy $tmp
}
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
"#;
    let _ = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .status();
    eprintln!("policy-helper: AppLocker launch deny cleared");
}

pub fn launch_paths(rules: &[AppDenyRule]) -> Vec<String> {
    launch_targets(rules)
        .into_iter()
        .filter_map(|target| match target {
            LaunchTarget::Path(path) => Some(path),
            _ => None,
        })
        .collect()
}

pub fn launch_targets(rules: &[AppDenyRule]) -> Vec<LaunchTarget> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for rule in rules {
        let Some(target) = launch_target(rule) else {
            continue;
        };
        let key = match &target {
            LaunchTarget::Path(path) => format!("path:{}", path.to_ascii_lowercase()),
            LaunchTarget::Hash(hex) => format!("hash:{hex}"),
            LaunchTarget::Publisher(name) => format!("publisher:{}", name.to_ascii_lowercase()),
        };
        if seen.insert(key) {
            out.push(target);
        }
    }
    out
}

fn launch_target(rule: &AppDenyRule) -> Option<LaunchTarget> {
    match rule.kind {
        AppMatchKind::Path => applocker_path(&rule.value).map(LaunchTarget::Path),
        AppMatchKind::Hash => normalize_sha256(&rule.value).map(LaunchTarget::Hash),
        AppMatchKind::Publisher => {
            let name = rule.value.trim();
            is_safe_publisher(name).then(|| LaunchTarget::Publisher(name.to_string()))
        }
    }
}

pub fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

pub fn is_safe_publisher(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.len() < 3 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    !lower.contains("microsoft corporation")
        && !lower.contains("microsoft windows")
        && !lower.contains("windows publisher")
}

pub fn applocker_path(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !is_safe_deny_target(trimmed) {
        return None;
    }
    if trimmed.contains('\\') || trimmed.contains('/') {
        return Some(trimmed.replace('/', "\\"));
    }
    Some(format!("*\\{trimmed}"))
}

pub fn is_safe_deny_target(value: &str) -> bool {
    let lower = value.replace('/', "\\").to_ascii_lowercase();
    if lower.contains("\\windows\\") || lower.starts_with("c:\\windows") {
        return false;
    }
    if lower.contains("vmg-sentinel") || lower.contains("sentinel.exe") {
        return false;
    }
    let name = lower.rsplit('\\').next().unwrap_or(&lower);
    !matches!(
        name,
        "explorer.exe"
            | "dwm.exe"
            | "csrss.exe"
            | "winlogon.exe"
            | "services.exe"
            | "lsass.exe"
            | "smss.exe"
            | "svchost.exe"
            | "runtimebroker.exe"
            | "sihost.exe"
            | "taskhostw.exe"
            | "conhost.exe"
            | "fontdrvhost.exe"
            | "searchhost.exe"
            | "startmenuexperiencehost.exe"
            | "systemsettings.exe"
            | "systemsettingsadminflows.exe"
            | "systempropertiescomputername.exe"
            | "systempropertiesadvanced.exe"
            | "systempropertieshardware.exe"
            | "systempropertiesprotection.exe"
            | "systempropertiesremote.exe"
            | "systempropertiesperformance.exe"
            | "control.exe"
            | "applicationframehost.exe"
            | "taskmgr.exe"
            | "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "mmc.exe"
            | "regedit.exe"
            | "consent.exe"
            | "logonui.exe"
    )
}

pub fn rule_id(path: &str) -> String {
    let digest = Sha256::digest(format!("vmg-sentinel-applocker-exe:{path}").as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:x}{:02x}-a{:x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
        digest[5],
        digest[6] & 0x0f,
        digest[7],
        digest[8] & 0x0f,
        digest[9],
        digest[10],
        digest[11],
        digest[12],
        digest[13],
        digest[14],
        digest[15]
    )
}

pub fn exe_deny_xml(targets: &[LaunchTarget]) -> String {
    let mut rules = String::from(DEFAULT_EXE_ALLOWS);
    for target in targets {
        rules.push_str(&target_xml(target));
    }
    format!(
        r#"<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
{rules}  </RuleCollection>
{DEFAULT_APPX_ALLOWS}</AppLockerPolicy>
"#
    )
}

/// AppLocker Exe collections are default-deny once Enabled. Microsoft's own
/// default rules allow Windows and Program Files first, then a catch-all `*`.
/// We do **not** add "Allow Administrators *" — BYOD users are often admins
/// and that rule would let them launch Steam/Spotify during a session.
const DEFAULT_EXE_ALLOWS: &str = r#"    <FilePathRule Id="7c3f2d01-6e5b-4a22-8d9f-11c2d3e4f506" Name="VMG Sentinel allow Windows" Description="Microsoft-style default: keep OS binaries (Settings hosts, SystemProperties) allowed" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="8d4a3e12-7f6c-4b33-9e0a-22d3e4f50617" Name="VMG Sentinel allow Program Files" Description="Microsoft-style default: keep installed desktop apps allowed unless explicitly denied" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="6b2e1c90-5d4a-4f11-9c8e-00a1b2c3d4e6" Name="VMG Sentinel allow all" Description="Required deny-list baseline; without this, Enabled AppLocker blocks the whole device" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
"#;

/// Windows 11 Settings / This PC → Properties is a packaged app. Leaving Appx
/// NotConfigured is not reliable once AppIDSvc + Exe enforcement are on; the
/// Microsoft default is Enabled + allow all signed packaged apps. We do not
/// put any packaged apps on the deny list.
const DEFAULT_APPX_ALLOWS: &str = r#"  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="c3d4e5f6-7a8b-4c01-9d2e-10f1a2b3c4d5" Name="VMG Sentinel allow all packaged" Description="Required so Settings / This PC Properties stay usable while Exe deny-list is on" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
"#;

fn xml_is_safe_deny_list(xml: &str) -> bool {
    xml.contains("VMG Sentinel allow all")
        && xml.contains("VMG Sentinel allow Windows")
        && xml.contains("VMG Sentinel allow Program Files")
        && xml.contains("VMG Sentinel allow all packaged")
        && xml.contains("Action=\"Allow\"")
        && xml.contains("FilePathCondition Path=\"*\"")
        && xml.contains("%WINDIR%\\*")
        && xml.contains("%PROGRAMFILES%\\*")
        && xml.contains("RuleCollection Type=\"Appx\"")
        && xml.contains("PublisherName=\"*\"")
        && xml.contains("UserOrGroupSid=\"S-1-1-0\"")
}

fn target_xml(target: &LaunchTarget) -> String {
    match target {
        LaunchTarget::Path(path) => {
            let id = rule_id(&format!("path:{path}"));
            let name = format!("{RULE_PREFIX} {path}");
            format!(
                r#"    <FilePathRule Id="{id}" Name="{}" Description="VMG Sentinel session launch deny; removed when tracking stops" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="{}" />
      </Conditions>
    </FilePathRule>
"#,
                xml_escape(&name),
                xml_escape(path)
            )
        }
        LaunchTarget::Hash(hex) => {
            let id = rule_id(&format!("hash:{hex}"));
            let name = format!("{RULE_PREFIX} hash {hex}");
            format!(
                r#"    <FileHashRule Id="{id}" Name="{}" Description="VMG Sentinel session launch deny; removed when tracking stops" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="SHA256" Data="0x{hex}" SourceFileName="denied.exe" SourceFileLength="0" />
        </FileHashCondition>
      </Conditions>
    </FileHashRule>
"#,
                xml_escape(&name)
            )
        }
        LaunchTarget::Publisher(publisher) => {
            let id = rule_id(&format!("publisher:{publisher}"));
            let name = format!("{RULE_PREFIX} publisher {publisher}");
            format!(
                r#"    <FilePublisherRule Id="{id}" Name="{}" Description="VMG Sentinel session launch deny; removed when tracking stops" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="{}" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"#,
                xml_escape(&name),
                xml_escape(publisher)
            )
        }
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn write_temp_xml(xml: &str) -> Result<String, String> {
    let path = std::env::temp_dir().join(format!(
        "vmg-sentinel-applocker-{}.xml",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&path).map_err(|error| error.to_string())?;
    file.write_all(xml.as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

fn ensure_appid_service() {
    let _ = Command::new("sc.exe")
        .args(["config", "AppIDSvc", "start=", "auto"])
        .status();
    let _ = Command::new("sc.exe").args(["start", "AppIDSvc"]).status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AppDenyRule, AppMatchKind};

    #[test]
    fn filename_becomes_wildcard_path() {
        assert_eq!(applocker_path("steam.exe").as_deref(), Some("*\\steam.exe"));
    }

    #[test]
    fn rejects_windows_and_shell() {
        assert!(applocker_path(r"C:\Windows\System32\notepad.exe").is_none());
        assert!(applocker_path("taskmgr.exe").is_none());
        assert!(applocker_path("cmd.exe").is_none());
        assert!(applocker_path("systemsettings.exe").is_none());
        assert!(applocker_path("systemsettingsadminflows.exe").is_none());
        assert!(applocker_path("systempropertiescomputername.exe").is_none());
        assert!(applocker_path("control.exe").is_none());
        assert!(applocker_path("vmg-sentinel-helper.exe").is_none());
    }

    #[test]
    fn xml_contains_deny_rule() {
        let xml = exe_deny_xml(&[LaunchTarget::Path("*\\spotify.exe".into())]);
        assert!(xml.contains("Action=\"Deny\""));
        assert!(xml.contains("*\\spotify.exe"));
        assert!(xml.contains(RULE_PREFIX));
        assert!(xml.contains(&rule_id("path:*\\spotify.exe")));
        assert!(xml.contains("Action=\"Allow\""));
        assert!(xml.contains("VMG Sentinel allow all"));
        assert!(xml.contains("VMG Sentinel allow Windows"));
        assert!(xml.contains("VMG Sentinel allow Program Files"));
        assert!(xml.contains("VMG Sentinel allow all packaged"));
        assert!(xml.contains("%WINDIR%\\*"));
        assert!(xml.contains("%PROGRAMFILES%\\*"));
        assert!(xml.contains("RuleCollection Type=\"Appx\""));
        assert!(xml.contains("FilePathCondition Path=\"*\""));
        assert!(xml_is_safe_deny_list(&xml));
    }

    #[test]
    fn refuses_xml_without_packaged_allow() {
        let exe_only = r#"<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="6b2e1c90-5d4a-4f11-9c8e-00a1b2c3d4e6" Name="VMG Sentinel allow all" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>"#;
        assert!(!xml_is_safe_deny_list(exe_only));
    }

    #[test]
    fn refuses_deny_only_xml() {
        let unsafe_xml = r#"<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Action="Deny"><Conditions><FilePathCondition Path="*\steam.exe" /></Conditions></FilePathRule>
  </RuleCollection>
</AppLockerPolicy>"#;
        assert!(!xml_is_safe_deny_list(unsafe_xml));
    }

    #[test]
    fn xml_contains_hash_and_publisher() {
        let hex = "A".repeat(64);
        let xml = exe_deny_xml(&[
            LaunchTarget::Hash(hex.clone()),
            LaunchTarget::Publisher("O=Valve Corp.".into()),
        ]);
        assert!(xml.contains("FileHashRule"));
        assert!(xml.contains(&format!("0x{hex}")));
        assert!(xml.contains("FilePublisherRule"));
        assert!(xml.contains("PublisherName=\"O=Valve Corp.\""));
        assert!(xml.contains("ProductName=\"*\""));
    }

    #[test]
    fn launch_targets_export_path_hash_and_safe_publisher() {
        let hex = "b".repeat(64);
        let rules = [
            AppDenyRule {
                kind: AppMatchKind::Path,
                alg: None,
                value: "steam.exe".into(),
            },
            AppDenyRule {
                kind: AppMatchKind::Hash,
                alg: Some("sha256".into()),
                value: hex.clone(),
            },
            AppDenyRule {
                kind: AppMatchKind::Hash,
                alg: Some("sha256".into()),
                value: "abcd".into(),
            },
            AppDenyRule {
                kind: AppMatchKind::Publisher,
                alg: None,
                value: "O=Spotify AB".into(),
            },
            AppDenyRule {
                kind: AppMatchKind::Publisher,
                alg: None,
                value: "O=Microsoft Corporation, L=Redmond, S=Washington, C=US".into(),
            },
        ];
        assert_eq!(
            launch_targets(&rules),
            vec![
                LaunchTarget::Path("*\\steam.exe".into()),
                LaunchTarget::Hash(hex.to_ascii_uppercase()),
                LaunchTarget::Publisher("O=Spotify AB".into()),
            ]
        );
    }
}
