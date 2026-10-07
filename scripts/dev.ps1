#requires -Version 7
<#
.SYNOPSIS
    SandTree 开发环境包装器。

.DESCRIPTION
    本机 Rust 未加入 PATH（rustup shim 缺失），工具链本体存在于
    %USERPROFILE%\.rustup\toolchains\1.98-x86_64-pc-windows-msvc。
    本脚本把 toolchain 与 MSVC 环境注入当前进程后转发给 cargo。

.EXAMPLE
    .\scripts\dev.ps1 build --release
    .\scripts\dev.ps1 test --workspace
    .\scripts\dev.ps1 fmt --all -- --check
    .\scripts\dev.ps1 clippy --workspace --all-targets -- -D warnings
    .\scripts\dev.ps1 gate            # 依次执行 fmt / clippy / test
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs = @('build')
)

$ErrorActionPreference = 'Stop'

$Toolchain = Join-Path $env:USERPROFILE '.rustup\toolchains\1.98-x86_64-pc-windows-msvc'
if (-not (Test-Path (Join-Path $Toolchain 'bin\cargo.exe'))) {
    throw "Rust toolchain not found at $Toolchain. Install via rustup first."
}

$env:RUSTUP_HOME = Join-Path $env:USERPROFILE '.rustup'
$env:CARGO_HOME = Join-Path $env:USERPROFILE '.cargo'
$env:PATH = "$Toolchain\bin;$env:PATH"

# MSVC: 让 cargo/rustc 能找到 link.exe 与 Windows SDK 头文件
$VsRoot = 'D:\Program Files\Microsoft Visual Studio\2022\Community'
if (Test-Path $VsRoot) {
    $vcvars = Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (Test-Path $vcvars) {
        $out = & cmd /c "`"$vcvars`" >nul 2>&1 && set" 2>$null
        foreach ($line in $out) {
            if ($line -match '^([^=]+)=(.*)$') {
                if ($matches[1] -eq 'PATH') { $env:PATH = "$($matches[2]);$env:PATH" }
                else { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] }
            }
        }
    }
}

Push-Location (Join-Path $PSScriptRoot '..')
try {
    & (Join-Path $Toolchain 'bin\cargo.exe') @CargoArgs
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}