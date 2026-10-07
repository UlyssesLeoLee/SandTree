<#
.SYNOPSIS
    Runs the four design gates (UT / IT / ST / UAT) plus the frozen-contract
    check, and records machine-readable evidence for every design test case.

.DESCRIPTION
    The design baseline defines 159 test cases in tests/test_cases.json with a
    Status and an Evidence column. Both are still "Not Executed"/empty, and the
    file is read-only, so the evidence has to live somewhere else. This script
    is that somewhere: it runs the gates, keeps the raw logs, and hands them to
    collect_evidence.py, which joins the logs against mock/scripts/case_map.csv
    and writes mock/evidence/coverage_matrix.csv.

    Gates, in dependency order:

      contract  the frozen schemas/WIT/DDL the implementation must match
      ut        unit tests -- every --lib target except the mock crates
      mock      the mock crates' own suite, every target
      it        integration tests -- tests/integration
      st        system tests    -- tests/system
      uat       acceptance contracts -- tests/uat, driven by the mock crates

    `ut` excludes the mock crates and `mock` runs them in full, because a test
    target that belongs to two gates is counted twice in the coverage check
    below and inflates it.

    A gate failing does not stop the run. The point of the evidence matrix is
    to show every layer at once, so each gate's exit code is recorded next to
    its log and the run continues. The script's own exit code is non-zero if
    any gate failed, so CI still sees a red build.

    The run finishes with a coverage check: it asks cargo to list every test the
    workspace owns and compares that with what the gates actually executed. A
    gate set that silently stops covering a package looks exactly like a
    passing run, so the check fails loudly when the two disagree.

.PARAMETER RunName
    Identifier for this run. Defaults to a UTC timestamp.

.PARAMETER SkipContract
    Skip the contract gate (it is the slowest and rarely the thing you are
    iterating on).

.PARAMETER TargetDir
    Cargo target directory. Defaults to E:\DevCache\cargo\target-dev -- the same
    one the development loop builds into. It is set **unconditionally**, not
    only when unset: an ambient CARGO_TARGET_DIR pointing elsewhere would make
    this script cold-build a different tree than the one every green run before
    it was validated against, so "the gate passed" and "the build I was looking
    at" would quietly refer to two different compilations.

.EXAMPLE
    .\run_regression.ps1
    Full four-gate run with evidence.

.EXAMPLE
    .\run_regression.ps1 -SkipContract
    Same, minus the frozen-contract check.
#>
[CmdletBinding()]
param(
    [string] $RunName = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    [switch] $SkipContract,
    [string] $TargetDir = 'E:\DevCache\cargo\target-dev'
)

$ErrorActionPreference = 'Continue'

$RepoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$EvidenceDir = Join-Path $RepoRoot 'mock\evidence'
$RunDir      = Join-Path $EvidenceDir "runs\$RunName"

# Rust is not on PATH in this environment and CARGO_HOME is not the default
# location, so both are injected explicitly rather than inherited. Silently
# relying on the ambient environment is how a gate ends up "passing" because it
# used a different toolchain than the one the lockfile was written against.
$env:RUSTUP_HOME = "$env:USERPROFILE\.rustup"
$env:CARGO_HOME  = 'E:\DevCache\cargo'
$ToolchainBin   = "$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin"
if (Test-Path $ToolchainBin) { $env:PATH = "$ToolchainBin;$env:PATH" }
$env:CARGO_TARGET_DIR = $TargetDir

# Fail loudly rather than run against a different tree than we record. An
# evidence file whose `cargo_target` does not match the build that was actually
# exercised is worse than no evidence file.
$resolved = (Resolve-Path -LiteralPath $TargetDir -ErrorAction SilentlyContinue)
if (-not $resolved) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}
Write-Output "cargo target : $env:CARGO_TARGET_DIR"

New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

function Write-Section {
    param([string] $Text)
    Write-Output ''
    Write-Output "=== $Text ==="
}

function Invoke-Gate {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string[]] $CargoArgs
    )
    $log = Join-Path $RunDir "$Name.log"
    # Progress goes to the host stream, never to the pipeline: a PowerShell
    # function returns *everything* it writes, so a `Write-Output` here would
    # make the caller receive `["--- gate: ...", "    exit=0 ...", 0]`. The
    # `if ($c -ne 0)` test on that array is truthy even when cargo returned 0,
    # which reported five green gates as five failures.
    Write-Host "--- gate: $Name  ($($CargoArgs -join ' '))"
    & cargo @CargoArgs *>&1 | Out-File -FilePath $log -Encoding utf8
    $code = $LASTEXITCODE
    Set-Content -Path (Join-Path $RunDir "$Name.exit") -Value $code -Encoding ascii
    $pass = (Select-String -Path $log -Pattern '^test result: ok\. (\d+) passed' |
             ForEach-Object { [int]$_.Matches[0].Groups[1].Value } | Measure-Object -Sum).Sum
    $fail = (Select-String -Path $log -Pattern '^test result: FAILED\. (\d+) failed' |
             ForEach-Object { [int]$_.Matches[0].Groups[1].Value } | Measure-Object -Sum).Sum
    Write-Host ("    exit={0}  passed={1}  failed={2}" -f $code, ($pass ?? 0), ($fail ?? 0))
    return [int]$code
}

# --- environment profile ----------------------------------------------------
# The UAT design requires every execution to record a build id and an
# environment profile. Without them an evidence file cannot be tied to a build.
$profile = [ordered]@{
    run_name      = $RunName
    build_id      = (git -C $RepoRoot rev-parse HEAD).Trim()
    branch        = (git -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim()
    dirty         = [bool](git -C $RepoRoot status --porcelain)
    rustc         = (& rustc --version)
    cargo         = (& cargo --version)
    cargo_target  = $env:CARGO_TARGET_DIR
    host_os       = [System.Environment]::OSVersion.VersionString
    docker_daemon = (& docker info --format '{{.ServerVersion}}' 2>&1 | Out-String).Trim()
}
$profile | ConvertTo-Json -Depth 3 |
    Set-Content -Path (Join-Path $RunDir 'environment.json') -Encoding utf8

Write-Output "run          : $RunName"
Write-Output "build        : $($profile.build_id.Substring(0,8)) ($($profile.branch))"
Write-Output "rustc        : $($profile.rustc)"
Write-Output "cargo target : $env:CARGO_TARGET_DIR"
Write-Output "docker       : $($profile.docker_daemon)"

$failures = @()

# --- gates ------------------------------------------------------------------
Set-Location $RepoRoot

if (-not $SkipContract) {
    $c = Invoke-Gate -Name 'contract' -CargoArgs @('test', '-p', 'sandtree-contract-tests', '--offline')
    if ($c -ne 0) { $failures += 'contract' }
}

# `--all-features` is load-bearing here, not decoration: without it the
# `#[cfg(feature = "wasmtime-abi")]` unit tests inside `crates/plugin-host`
# are never compiled, so they are never run, and nobody notices. That module is
# where the WASM adapter lives.
$c = Invoke-Gate -Name 'ut' -CargoArgs @(
    'test', '--workspace', '--all-features', '--offline', '--lib',
    '--exclude', 'sandtree-mock-runtime',
    '--exclude', 'sandtree-mock-observation',
    '--exclude', 'sandtree-mock-wasm-components'
)
if ($c -ne 0) { $failures += 'ut' }

# The mock crates are test assets, but they are also real crates with their own
# suite -- the fixture corpus, the ADR-OBS-001/003 proofs, the determinism
# checks. Nothing else in this script runs those targets, so without this gate a
# fixture could drift and every consumer would keep reporting green against a
# degraded fake.
$c = Invoke-Gate -Name 'mock' -CargoArgs @(
    'test', '--offline',
    '-p', 'sandtree-mock-runtime',
    '-p', 'sandtree-mock-observation',
    '-p', 'sandtree-mock-wasm-components'
)
if ($c -ne 0) { $failures += 'mock' }

# The `engine` module of `sandtree-mock-wasm-components` is behind a default-OFF
# feature, so the `mock` gate above never compiled it. It was red for as long as
# it existed -- seven failing tests -- and nothing said so, because a feature-gated
# module is also invisible to the coverage self-check below: `cargo test --list`
# does not list tests that are not compiled, so "the workspace owns N tests" was
# computed from a set that had already excluded them. That is the same shape as a
# lint rule that scans the wrong path and returns zero rows: the gap and the clean
# result look identical.
#
# So this gate exists, and the count assertion below it is what stops it from
# silently becoming a no-op if the feature is ever renamed or dropped.
$c = Invoke-Gate -Name 'mock-engine' -CargoArgs @(
    'test', '--offline',
    '-p', 'sandtree-mock-wasm-components',
    '--features', 'engine', '--lib'
)
if ($c -ne 0) { $failures += 'mock-engine' }

# A gate that compiles nothing passes. Pin the floor: if the engine module ever
# stops existing, this goes red instead of quietly contributing zero tests.
$engineLog = Join-Path $RunDir 'mock-engine.log'
if (Test-Path $engineLog) {
    $engineRan = @(Select-String -Path $engineLog -Pattern '^test engine::tests::').Count
    if ($engineRan -lt 1) {
        Write-Output ''
        Write-Output "ENGINE GAP      : the mock-engine gate ran 0 engine-gated tests."
        Write-Output '                  It passed, so it is worse than absent: the fixture corpus'
        Write-Output '                  is no longer validated by a real engine and the run is green.'
        $failures += 'mock-engine-coverage'
    } else {
        Write-Output "engine corpus   : $engineRan engine-gated tests executed"
    }
}

$c = Invoke-Gate -Name 'it' -CargoArgs @('test', '-p', 'sandtree-integration-tests', '--offline')
if ($c -ne 0) { $failures += 'it' }

$c = Invoke-Gate -Name 'st' -CargoArgs @('test', '-p', 'sandtree-system-tests', '--offline')
if ($c -ne 0) { $failures += 'st' }

$c = Invoke-Gate -Name 'uat' -CargoArgs @('test', '-p', 'sandtree-uat-tests', '--offline')
if ($c -ne 0) { $failures += 'uat' }

# ADR-015: the two network-acquisition channels carry end-to-end tests that
# open real loopback sockets and drive the production transport. They live in
# `tests/e2e.rs`, which the `ut` gate's `--lib` filter does not reach -- and a
# target no gate runs is indistinguishable from a target that passes. Two gates
# rather than one, because cargo takes a single `--test` and the evidence
# matrix is more useful when the two channels are separable.
$c = Invoke-Gate -Name 'git-channel' -CargoArgs @(
    'test', '--offline', '-p', 'sandtree-provider-git-remote', '--test', 'e2e'
)
if ($c -ne 0) { $failures += 'git-channel' }

$c = Invoke-Gate -Name 'mcp-channel' -CargoArgs @(
    'test', '--offline', '-p', 'sandtree-provider-mcp-remote', '--test', 'e2e'
)
if ($c -ne 0) { $failures += 'mcp-channel' }

# --- coverage self-check -----------------------------------------------------
# The gate list above is hand-written; the set of tests the workspace actually
# owns is not. This asks cargo for the second and compares it with the first, so
# "four gates green" cannot quietly mean "the gates I remembered to wire up are
# green". It is the same shape as a lint rule whose input set is discovered
# rather than hard-coded: a rule that scans the wrong path returns zero rows and
# looks exactly like a clean result.
Write-Section 'coverage'
$inventory = Join-Path $RunDir 'inventory.log'
& cargo test --workspace --offline -- --list *>&1 | Out-File -FilePath $inventory -Encoding utf8
$listed = @(Get-Content $inventory -Encoding utf8 | Where-Object { $_ -match ':\s+test$' })
# Doc-tests are listed as "src/lib.rs - foo (line 12)"; no gate runs them, so
# they are subtracted rather than silently widening the gap.
$doctests = @($listed | Where-Object { $_ -match '\s-\s' }).Count
$owned = $listed.Count - $doctests

# `--list` on the default feature set omits every feature-gated test, so the
# inventory above is a *subset* of what the workspace owns. The `engine` corpus
# was invisible to this check for exactly that reason: seven red tests, and a
# coverage report that said everything the workspace owns was covered. List the
# engine feature set too and add the difference.
$engineInventory = Join-Path $RunDir 'inventory-engine.log'
& cargo test --workspace --offline --features sandtree-mock-wasm-components/engine -- --list *>&1 |
    Out-File -FilePath $engineInventory -Encoding utf8
$engineListed = @(Get-Content $engineInventory -Encoding utf8 | Where-Object { $_ -match ':\s+test$' })
$engineDoctests = @($engineListed | Where-Object { $_ -match '\s-\s' }).Count
$engineOwned = $engineListed.Count - $engineDoctests
$engineOnly = [Math]::Max(0, $engineOwned - $owned)

$executed = 0
foreach ($gate in @('contract', 'ut', 'mock', 'mock-engine', 'it', 'st', 'uat', 'git-channel', 'mcp-channel')) {
    $log = Join-Path $RunDir "$gate.log"
    if (-not (Test-Path $log)) { continue }
    $n = (Select-String -Path $log -Pattern '^test result: ok\. (\d+) passed' |
          ForEach-Object { [int]$_.Matches[0].Groups[1].Value } | Measure-Object -Sum).Sum
    if ($n) { $executed += $n }
}
$ownedTotal = $owned + $engineOnly

Write-Output ("workspace owns : {0} tests ({1} doc-tests excluded)" -f $ownedTotal, $doctests)
if ($engineOnly -gt 0) {
    # Single-quoted body with a separate interpolated head: a backtick inside a
    # double-quoted PowerShell string escapes whatever follows it, and a trailing
    # backtick swallows the closing quote -- which parses as an unterminated
    # string much further down the file, far from the line that caused it.
    Write-Output ("                 of which {0} are feature-gated and invisible to a default --list" -f $engineOnly)
}
Write-Output ("gates executed  : {0} tests" -f $executed)
if ($executed -lt $ownedTotal) {
    $gap = $ownedTotal - $executed
    Write-Output ''
    Write-Output "COVERAGE GAP    : $gap test(s) the workspace owns are not run by any gate."
    Write-Output '                  A gate that does not cover a package looks exactly like a'
    Write-Output '                  passing one. Add the package to the gate list above.'
    $failures += 'coverage'
} else {
    Write-Output 'coverage        : every test the workspace owns is executed by a gate'
}

# --- evidence ---------------------------------------------------------------
Write-Section 'evidence'
& python (Join-Path $PSScriptRoot 'collect_evidence.py') $RunName
$evidenceExit = $LASTEXITCODE

Write-Output ''
Write-Output "raw logs      : mock/evidence/runs/$RunName/"
Write-Output "matrix        : mock/evidence/coverage_matrix.csv"
Write-Output "report        : mock/docs/REGRESSION.md"

if ($failures.Count -gt 0) {
    Write-Output ''
    Write-Output "FAILED GATES  : $($failures -join ', ')"
    exit 1
}
Write-Output ''
Write-Output 'all four gates green'
exit $evidenceExit
