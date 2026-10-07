<#
.SYNOPSIS
    Builds the SandTree Windows release package: release binaries, a staged
    install tree, a portable ZIP and a per-user MSI.

.DESCRIPTION
    The payload is four self-contained executables and nothing else. That is not
    a shortcut, it is what the code actually needs: `schemas/001_init.sql` and
    both WIT files are `include_str!`'d into the binaries at compile time, so
    there is no runtime data file to place. The kernel creates its own data
    directory under `%LOCALAPPDATA%\sandtree` on first run.

    Two artifacts come out of the same staged tree, so the ZIP and the MSI
    cannot drift apart:

      SandTree-<version>-x64.zip     portable; unpack anywhere and run
      SandTree-<version>-x64.msi     per-user installer, no elevation (NFR-S01)

.PARAMETER Version
    Product version stamped into the MSI, VERSION.txt and the file names.
    Defaults to the workspace version in Cargo.toml.

.PARAMETER SkipBuild
    Reuse the existing release binaries instead of rebuilding. Use it only when
    nothing in the sources changed since the last build; the manifest records
    the git SHA either way, so a stale package is traceable but still stale.

.PARAMETER SkipZip
.PARAMETER SkipMsi

.EXAMPLE
    .\package.ps1
    Build, stage, zip and MSI.

.EXAMPLE
    .\package.ps1 -SkipBuild -SkipMsi
    Re-stage and re-zip an existing release build.
#>
[CmdletBinding()]
param(
    [string] $Version,
    [switch] $SkipBuild,
    [switch] $SkipZip,
    [switch] $SkipMsi,
    [string] $WixTool = 'E:\DevCache\tools\wix.exe'
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistDir  = Join-Path $RepoRoot 'dist'
$StageDir = Join-Path $DistDir 'stage'

# The four executables the product is. A package that is missing one of these
# is not a smaller package, it is a broken one, and the check below is the only
# thing standing between a partial build and a shipped installer.
$Binaries = @(
    @{ Name = 'sandtree';               Crate = 'sandtree-cli' }
    @{ Name = 'sandtree-daemon';        Crate = 'sandtree-daemon' }
    @{ Name = 'sandtree-plugin-worker'; Crate = 'sandtree-plugin-worker' }
    @{ Name = 'probe-windows';          Crate = 'sandtree-probe-windows' }
)

# Rust is not on PATH in this environment and CARGO_HOME is not the default
# location. Both are injected explicitly, and CARGO_TARGET_DIR is assigned
# unconditionally rather than only when unset: an ambient value pointing
# elsewhere would build a different tree than the one the gates verified.
$env:RUSTUP_HOME = "$env:USERPROFILE\.rustup"
$env:CARGO_HOME  = 'E:\DevCache\cargo'
$ToolchainBin   = "$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin"
if (Test-Path $ToolchainBin) { $env:PATH = "$ToolchainBin;$env:PATH" }
$env:CARGO_TARGET_DIR = 'E:\DevCache\cargo\target-release'

function Write-Step { param([string] $Text) Write-Host "==> $Text" }

if (-not $Version) {
    $cargoToml = Get-Content (Join-Path $RepoRoot 'Cargo.toml') -Raw
    if ($cargoToml -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw 'could not read the workspace version out of Cargo.toml; pass -Version explicitly'
    }
    $Version = $matches[1]
}

$ProductName = "SandTree-$Version-x64"
$Stage       = Join-Path $StageDir $ProductName
$GitSha      = (git -C $RepoRoot rev-parse HEAD).Trim()
$Rustc       = (& rustc --version).Trim()

Write-Step "SandTree $ProductName"
Write-Host "    git  $GitSha"
Write-Host "    rustc $Rustc"

# --- build -------------------------------------------------------------------
$crates = $Binaries | ForEach-Object { $_.Crate }
if (-not $SkipBuild) {
    Write-Step 'building release binaries'
    Push-Location $RepoRoot
    try {
        & cargo build --release --offline @($crates | ForEach-Object { @('-p', $_) })
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit $LASTEXITCODE" }
    } finally { Pop-Location }
}

$ReleaseBin = Join-Path $env:CARGO_TARGET_DIR 'release'

# --- stage -------------------------------------------------------------------
Write-Step 'staging the install tree'
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
$stageBin = New-Item -ItemType Directory -Force -Path (Join-Path $Stage 'bin')

$missing = @()
foreach ($b in $Binaries) {
    $src = Join-Path $ReleaseBin "$($b.Name).exe"
    if (-not (Test-Path $src)) { $missing += "$($b.Name).exe"; continue }
    $size = (Get-Item $src).Length
    # A 0-byte or stub executable is worse than a missing one: the MSI builds
    # happily and the failure only shows up on the target machine.
    if ($size -lt 20KB) { $missing += "$($b.Name).exe (only $size bytes)"; continue }
    Copy-Item $src (Join-Path $stageBin "$($b.Name).exe")
}
if ($missing.Count -gt 0) {
    throw "release build is incomplete, refusing to package: $($missing -join ', ')"
}

Copy-Item (Join-Path $RepoRoot 'LICENSE') (Join-Path $Stage 'LICENSE')

# --- manifest ----------------------------------------------------------------
# SHA-256 over every shipped executable, sorted by name so two builds of the
# same tree produce byte-identical manifests. Without the sort the file differs
# run to run and stops being usable as a check.
$manifestLines = @()
foreach ($b in $Binaries | Sort-Object Name) {
    $file = Join-Path $Stage "bin/$($b.Name).exe"
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestLines += "$hash  bin/$($b.Name).exe"
}
[System.IO.File]::WriteAllLines(
    (Join-Path $Stage 'MANIFEST.sha256'),
    $manifestLines,
    (New-Object System.Text.UTF8Encoding($false)))

$versionText = @(
    "name        SandTree"
    "version     $Version"
    "git         $GitSha"
    "branch      $((git -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim())"
    "built       $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    "rustc       $Rustc"
    "target      x86_64-pc-windows-msvc"
    ""
    "payload     bin\sandtree.exe               CLI"
    "            bin\sandtree-daemon.exe        daemon (per-user, no elevation)"
    "            bin\sandtree-plugin-worker.exe plugin sandbox worker"
    "            bin\probe-windows.exe          Windows Sandbox probe (NFR-S07)"
) -join "`r`n"
[System.IO.File]::WriteAllText(
    (Join-Path $Stage 'VERSION.txt'), $versionText + "`r`n",
    (New-Object System.Text.UTF8Encoding($false)))

$installText = @"
SandTree $Version — 安装后怎么用
================================

安装位置    %LOCALAPPDATA%\Programs\SandTree
数据目录    %LOCALAPPDATA%\sandtree        （首次运行 daemon 时自动创建）
IPC         \\.\pipe\sandtree-<当前用户>-v1  （按用户隔离，不提权）

本安装**不修改 PATH**。安装器的环境变量接口是覆盖而不是追加，
一个会悄悄改掉你 PATH 的安装程序，比让你自己加一个目录糟糕得多。
要加的话，二选一：

  当前会话生效
      `$env:PATH += ";$env:LOCALAPPDATA\Programs\SandTree\bin"

  永久生效（只影响你的账户，不影响系统其它用户）
      [Environment]::SetEnvironmentVariable(
          'Path',
          [Environment]::GetEnvironmentVariable('Path','User') + ";$env:LOCALAPPDATA\Programs\SandTree\bin",
          'User')

## 验证装好了

    sandtree --version
    sandtree-daemon --help

## 跑起来

    sandtree-daemon                # 前台启动 daemon
    sandtree resource.list         # 另开一个窗口

## 卸载

  MSI：设置 → 应用 → SandTree → 卸载。
  ZIP：删掉解压出来的目录即可。数据目录独立于安装目录，
       %LOCALAPPDATA%\sandtree 里的 SQLite 与 CAS 不会被删 —— 它们是你的数据，
       要清就自己删。

## 这个包里没有什么

  * 没有 desktop GUI。设计基线把 Tauri 2 列为 MUST，但本仓还没有 UI 层
    （见 mock/evidence/coverage_matrix.csv 里 ST-003 / ST-026 两条 UNMAPPED）。
  * 没有 schemas/ 和 wit/。它们被 `include_str!` 编译进二进制了，运行期不需要。
  * 没有 Windows 服务。daemon 是按用户跑的，设计上就是 NFR-S01 那一类。
"@
[System.IO.File]::WriteAllText(
    (Join-Path $Stage 'INSTALL.txt'), $installText.Replace("`n", "`r`n"),
    (New-Object System.Text.UTF8Encoding($false)))

$readmeText = @"
# SandTree v$Version

Sandbox & Docker Control Plane。本包安装的是命令行与 daemon，不是 GUI。

上手先读同目录的 ``INSTALL.txt``。

设计基线：v1.1 Observation Plane。Control Plane 与 Observation Plane 分离，
Trust 只降不升，隔离不可交易。完整说明见仓库
https://github.com/UlyssesLeoLee/SandTree

许可：Apache-2.0，见同目录 ``LICENSE``。第三方依赖许可见
``MANIFEST.sha256`` 之外的仓库 ``docs/`` 与 ``schemas/deny.toml``。
"@
[System.IO.File]::WriteAllText(
    (Join-Path $Stage 'README.md'), $readmeText.Replace("`n", "`r`n"),
    (New-Object System.Text.UTF8Encoding($false)))

$stageBytes = (Get-ChildItem $Stage -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host ("    staged {0} files, {1:N2} MB" -f (Get-ChildItem $Stage -Recurse -File).Count, ($stageBytes / 1MB))

# --- zip ---------------------------------------------------------------------
if (-not $SkipZip) {
    Write-Step 'building the portable zip'
    $zip = Join-Path $DistDir "$ProductName.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # includeBaseDirectory = true: the archive must contain a named folder, or
    # extracting it into Downloads scatters nine loose files across it. The MSI
    # already installs under %LOCALAPPDATA%\Programs\SandTree; the ZIP has to
    # land in a directory of its own for the two to behave the same.
    [System.IO.Compression.ZipFile]::CreateFromDirectory($Stage, $zip,
        [System.IO.Compression.CompressionLevel]::Optimal, $true)
    Write-Host ("    {0}  ({1:N2} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
}

# --- msi ---------------------------------------------------------------------
if (-not $SkipMsi) {
    if (-not (Test-Path $WixTool)) {
        throw "WiX not found at $WixTool. Install it with: dotnet tool install --tool-path E:\DevCache\tools wix --version 5.0.2"
    }
    # WiX v5 is the last MIT-licensed line. v6+ demands the OSMF EULA be
    # accepted, and accepting a licence on the user's behalf is not this
    # script's call to make.
    $wixVersion = (& $WixTool --version).Trim()
    if (-not $wixVersion.StartsWith('5.')) {
        throw ("expected WiX 5.x at {0}, found {1}. v6+ requires accepting the OSMF " +
               "EULA; install the MIT-licensed line with: dotnet tool install " +
               "--tool-path E:\DevCache\tools wix --version 5.0.2") -f $WixTool, $wixVersion
    }
    Write-Step "building the MSI (WiX $wixVersion)"
    $msi = Join-Path $DistDir "$ProductName.msi"
    if (Test-Path $msi) { Remove-Item -Force $msi }
    Push-Location $RepoRoot
    try {
        & $WixTool build 'wix\main.wxs' `
            -d "ProductVersion=$Version" `
            -d "SourceDir=$Stage" `
            -o $msi
        if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit $LASTEXITCODE" }
    } finally { Pop-Location }
    Write-Host ("    {0}  ({1:N2} MB)" -f $msi, ((Get-Item $msi).Length / 1MB))
}

Write-Step 'done'
Get-ChildItem $DistDir -File | ForEach-Object { Write-Host ("    {0}  {1:N2} MB" -f $_.Name, ($_.Length / 1MB)) }
exit 0
