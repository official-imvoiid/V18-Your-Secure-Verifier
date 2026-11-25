; V18 for Windows: register the v18:// link type for this user (electron-builder's "protocols"
; option only works on macOS). V18 also re-registers itself on start with
; app.setAsDefaultProtocolClient, which writes the same keys.

!macro customInstall
  DetailPrint "Registering v18:// links"
  WriteRegStr SHELL_CONTEXT "Software\Classes\v18" "" "URL:V18 age check"
  WriteRegStr SHELL_CONTEXT "Software\Classes\v18" "URL Protocol" ""
  WriteRegStr SHELL_CONTEXT "Software\Classes\v18\DefaultIcon" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME},0"
  WriteRegStr SHELL_CONTEXT "Software\Classes\v18\shell\open\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'
!macroend

!macro customUnInstall
  ; The v18:// link type.
  DeleteRegKey SHELL_CONTEXT "Software\Classes\v18"
  ; "Start V18 when I sign in to Windows" (Electron names the value after the app ID).
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "com.v18.desktop"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "com.v18.desktop"
!macroend
