# Wrapper kept for local Windows use. The real generator is make-icon.js
# (BMP-only ICO, small installer icon for NSIS).
& node (Join-Path $PSScriptRoot "make-icon.js")
if ($LASTEXITCODE -ne 0) { throw "make-icon.js failed" }
