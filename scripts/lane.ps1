# Lane-local build/test helper.
#
# Why this exists: CARGO_TARGET_DIR is set globally to E:\DevCache\cargo\target,
# which every worktree would share. Concurrent cargo invocations against one
# target directory serialise on the package-cache lock, so three parallel lanes
# would effectively build one at a time. Each lane therefore gets its own
# target directory under target-lanes\<lane>.
#
# Usage from anywhere:
#   .\scripts\lane.ps1 gate     # fmt --check + clippy -D warnings + test + license gate
#   .\scripts\lane.ps1 test
#   .\scripts\lane.ps1 clippy

$ErrorActionPreference = 'Stop'

# Lane root = parent of the scripts/ directory holding this file.
$laneRoot = Split-Path -Parent $PSScriptRoot
$lane = Split-Path -Leaf $laneRoot
Set-Location $laneRoot

# --- toolchain (cargo is not on PATH on this machine) -------------------------
$env:RUSTUP_HOME = "$env:USERPROFILE\.rustup"
$env:PATH = "$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin;$env:PATH"

# --- isolated build + registry ------------------------------------------------
# CARGO_HOME points at the local-disk registry that holds the vendored crates;
# offline builds resolve from there, so it must NOT be reset to ~/.cargo.
$env:CARGO_HOME = "E:\DevCache\cargo"
$env:CARGO_TARGET_DIR = "E:\DevCache\cargo\target-lanes\$lane"

$cmd = if ($args.Count -ge 1) { $args[0] } else { 'gate' }

function Fail([string]$what) { throw "$what failed in lane '$lane'" }

switch ($cmd) {
    'fmt'    { cargo fmt --all -- --check }
    'fix'    { cargo fmt --all }
    'clippy' { cargo clippy --workspace --all-targets --offline -- -D warnings }
    'test'   { cargo test --workspace --offline }
    'gate'   {
        cargo fmt --all -- --check
        if ($LASTEXITCODE -ne 0) { Fail 'fmt check' }
        cargo clippy --workspace --all-targets --offline -- -D warnings
        if ($LASTEXITCODE -ne 0) { Fail 'clippy' }
        cargo test --workspace --offline
        if ($LASTEXITCODE -ne 0) { Fail 'tests' }
        python scripts\license_gate.py
        if ($LASTEXITCODE -ne 0) { Fail 'license gate' }
        Write-Output "GATE OK ($lane)"
    }
    default  { throw "unknown command '$cmd' (use fmt|fix|clippy|test|gate)" }
}

exit $LASTEXITCODE
