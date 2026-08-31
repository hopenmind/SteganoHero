; NSIS installer hooks for the SteganoHero Windows installer (Tauri v2).
;
; Tauri's NSIS template creates the Start-menu shortcut. A DESKTOP shortcut is
; added here, on install, and removed on uninstall, using the template's own
; defined variables (PRODUCTNAME, MAINBINARYNAME). Referenced from
; tauri.conf.json as bundle.windows.nsis.installerHooks.

!macro NSIS_HOOK_POSTINSTALL
  CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Delete "$DESKTOP\${PRODUCTNAME}.lnk"
!macroend
