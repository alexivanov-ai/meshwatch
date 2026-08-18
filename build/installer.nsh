; electron-builder defaults to hiding the InstFiles detail pane
; (ShowInstDetails nevershow + SetDetailsPrint none). Undo that so users
; can see each file as it is copied and the post-install steps below.
!macro customHeader
  ShowInstDetails show
  ShowUninstDetails show
!macroend

!macro customInstall
  DetailPrint "Registering Meshwatch with Windows (Apps & features)..."
  DetailPrint "Creating Start menu shortcut..."
  DetailPrint "Creating desktop shortcut (if enabled)..."
!macroend

!macro customUnInstall
  DetailPrint "Removing Meshwatch program files from $INSTDIR..."
  DetailPrint "Removing shortcuts and registry entries..."
!macroend
