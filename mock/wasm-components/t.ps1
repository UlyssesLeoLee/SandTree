# Lane C temporary helper: run the engine-gated fixture tests.
# Kills any stale test exe first (link.exe on this machine intermittently
# fails with LNK1104 on a locked/undeletable previous exe).
$ErrorActionPreference = 'Stop'
$laneRoot = Split-Path -Parent $PSScriptRoot
Set-Location $laneRoot
$env:RUSTUP_HOME = "$env:USERPROFILE\.rustup"
$env:PATH = "$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin;$env:PATH"
$env:CARGO_HOME = "E:\DevCache\cargo"
$env:CARGO_TARGET_DIR = "E:\DevCache\cargo\target-lanes\c-mock-wasm"
Get-Process | Where-Object { $_.ProcessName -like '*wasm_components*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Get-ChildItem "$env:CARGO_TARGET_DIR\debug\deps" -Filter 'sandtree_mock_wasm_components-*.exe' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
cargo test -p sandtree-mock-wasm-components @args --offline
exit $LASTEXITCODE
