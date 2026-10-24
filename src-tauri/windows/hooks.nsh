; Place wintun.dll beside the executable. The helper looks there first and also
; accepts the Tauri resources directory if the copy is unnecessary.
!macro NSIS_HOOK_POSTINSTALL
  IfFileExists "$INSTDIR\wintun.dll" wintun_done 0
  IfFileExists "$INSTDIR\resources\wintun.dll" 0 wintun_done
  CopyFiles /SILENT "$INSTDIR\resources\wintun.dll" "$INSTDIR\wintun.dll"
  wintun_done:
!macroend
