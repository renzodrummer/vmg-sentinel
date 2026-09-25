!include LogicLib.nsh

!macro customInit
  nsExec::ExecToLog 'net stop VMGSentinelHelper'
  Sleep 1500
!macroend

!macro customInstall
  DetailPrint "Registering VMG Sentinel policy helper (LocalSystem)"
  IfFileExists "$INSTDIR\resources\policy-helper\vmg-sentinel-helper.exe" 0 helper_missing
  nsExec::ExecToLog '"$INSTDIR\resources\policy-helper\vmg-sentinel-helper.exe" --install'
  Pop $0
  ${If} $0 != 0
    DetailPrint "Helper --install exited with code $0"
  ${EndIf}
  Goto helper_done
  helper_missing:
    DetailPrint "policy-helper binary missing; site/app blocking will not start"
  helper_done:
!macroend

!macro customUnInstall
  IfFileExists "$INSTDIR\resources\policy-helper\vmg-sentinel-helper.exe" 0 helper_uninst_sc
  nsExec::ExecToLog '"$INSTDIR\resources\policy-helper\vmg-sentinel-helper.exe" --clear-blocks'
  nsExec::ExecToLog '"$INSTDIR\resources\policy-helper\vmg-sentinel-helper.exe" --uninstall'
  Pop $0
  Goto helper_uninst_done
  helper_uninst_sc:
    nsExec::ExecToLog 'powershell.exe -NoProfile -Command "Get-NetFirewallRule -DisplayGroup ''VMG Sentinel'' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue"'
    nsExec::ExecToLog 'sc.exe stop VMGSentinelHelper'
    nsExec::ExecToLog 'sc.exe delete VMGSentinelHelper'
  helper_uninst_done:
!macroend
