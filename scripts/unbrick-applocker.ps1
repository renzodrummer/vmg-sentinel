# Recovery only for a machine stuck by an old helper. Real users never run this.
# Production path: Start Tracking applies rules; Stop Tracking / Quit clears them
# via the LocalSystem service (SetSession false). Run as Administrator.
$ErrorActionPreference = 'Stop'
$file = Join-Path $env:TEMP 'vmg-sentinel-unbrick-applocker.xml'
@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
'@ | Set-Content -LiteralPath $file -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $file
Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayGroup 'VMG Sentinel' -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host 'AppLocker Exe is NotConfigured. VMG Sentinel firewall rules removed.'
Write-Host 'Steam, Spotify, Discord, and Photos should open again.'
