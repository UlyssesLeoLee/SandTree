#!/usr/bin/env python3
"""Offline stand-in for `cargo deny check licenses` + `check sources`.

Why this exists
---------------
The repo gate requires `cargo deny check` (NFR-E03 / schemas/deny.toml), but this
machine has no `cargo-deny` binary and `cargo install` needs network access that is
not available. Rather than silently dropping the gate, this script audits the same
two questions itself:

  1. licenses : every third-party package's license, for the exact version pinned in
                Cargo.lock, must satisfy schemas/deny.toml's `[licenses].allow` list.
  2. sources  : every third-party package must come from crates.io; git sources are
                denied per `[sources] unknown-git = "deny"`.

Where the license data comes from, and why
-----------------------------------------
Three places were tried; the first two were wrong in ways that silently produced
false verdicts, so the choice matters:

  * Cargo.lock          -- WRONG. It records name/version/source/checksum/deps only.
                           There is no `license` field, so every package looks
                           "undeterminable": 273 false violations.
  * registry/index/<i>/.cache/... -- WRONG. This is cargo's sparse-index cache and
                           it does NOT carry the `license` key (verified against
                           wasmtime 38.0.4: the entry ends at `"v":2}` with no
                           license field), so every lookup misses.
  * registry/src/<n>-<v>/Cargo.toml -- PARTIAL. Only crates cargo has unpacked are
                           present; a `cargo fetch`-only machine has 218 of 273,
                           leaving 55 blind spots.
  * registry/cache/<i>/<n>-<v>.crate -- USED as the authoritative fallback. This is
                           the exact published tarball whose sha256 Cargo.lock pins,
                           and it always contains `<n>-<v>/Cargo.toml` with the
                           license field. registry/src is still preferred when
                           present because it avoids decompressing.

SPDX evaluation semantics (matching cargo-deny)
-----------------------------------------------
  * `A OR B`            -> ACCEPT if ANY branch is allowed. The consumer may choose
                           either license, so one acceptable option is enough.
                           (`Unlicense OR MIT` passes because MIT is allowed.)
  * `A AND B`           -> ALL terms must be allowed.
  * `A/B`               -> legacy SPDX 2.1 spelling of `A OR B`; normalised before
                           evaluation. (`MIT/Apache-2.0` is not a violation.)
  * `A WITH B`          -> kept intact as one identifier; no splitting.
  * parenthesised groups -> unwrapped, then evaluated with the rules above.

Self-disabling thresholds
-------------------------
A gate that silently scans nothing looks exactly like a gate that found no problems.
This script therefore FAILs, loudly, whenever it is blind:
  * zero third-party packages parsed                -> scanner saw nothing
  * no registry index cache and no registry src     -> no metadata source at all
  * any package whose license cannot be determined   -> FAIL, never skip
  * a metadata source that yields zero licenses     -> FAIL, scanner is blind

Exit code 0 = gate pass, 1 = gate fail.
"""

from __future__ import annotations

import os
import re
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "Cargo.lock"
DENY = ROOT / "schemas" / "deny.toml"

# Cargo.lock sources for crates.io: the sparse index is what current cargo writes;
# the git index URL is the older spelling, accepted for lockfile portability.
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}


def load_allow_list() -> set[str]:
    data = tomllib.loads(DENY.read_text(encoding="utf-8"))
    return set(data["licenses"].get("allow", []))


def cargo_homes() -> list[Path]:
    """Every plausible CARGO_HOME, most specific first.

    A machine can have more than one: this repo runs with `CARGO_HOME` pointed at a
    fast local disk while the rustup-installed toolchain still unpacks into
    `%USERPROFILE%/.cargo`. Scanning only one silently leaves the other half of the
    dependency set undeterminable, which looks identical to "no license problems".
    """
    seen: list[Path] = []
    for candidate in (
        os.environ.get("CARGO_HOME"),
        os.environ.get("RUSTUP_HOME"),
        str(Path.home() / ".cargo"),
    ):
        if not candidate:
            continue
        p = Path(candidate)
        if p not in seen:
            seen.append(p)
    return seen


def _roots_under(sub: str) -> list[Path]:
    roots: list[Path] = []
    for home in cargo_homes():
        base = home / "registry" / sub
        if not base.is_dir():
            continue
        roots.extend(sorted(p for p in base.iterdir() if p.is_dir()))
    return roots


def index_cache_roots() -> list[Path]:
    return _roots_under("index")


def registry_src_roots() -> list[Path]:
    return _roots_under("src")


def parse_lock(text: str) -> list[tuple[str, str, str | None]]:
    """Yield (name, version, source) for each [[package]] in Cargo.lock."""
    out: list[tuple[str, str, str | None]] = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        src = re.search(r'^source\s*=\s*"([^"]+)"', block, re.M)
        if name and ver:
            out.append((name.group(1), ver.group(1), src.group(1) if src else None))
    return out


def license_from_registry_src(roots: list[Path], name: str, version: str) -> str | None:
    """Read the license from an already-unpacked crate in the registry src tree."""
    for root in roots:
        manifest = root / f"{name}-{version}" / "Cargo.toml"
        if not manifest.is_file():
            continue
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001 - one bad manifest must not kill the gate
            return None
        pkg = data.get("package", {})
        lic = pkg.get("license")
        if isinstance(lic, str) and lic.strip():
            return lic.strip()
        if pkg.get("license-file"):
            return "license-file:" + str(pkg["license-file"])
    return None


def registry_cache_roots() -> list[Path]:
    return _roots_under("cache")


def license_from_crate_tarball(roots: list[Path], name: str, version: str) -> str | None:
    """Read the license out of the published `.crate` tarball.

    The tarball is the exact artifact whose sha256 Cargo.lock pins, and it always
    carries `<name>-<version>/Cargo.toml`, so this resolves licenses for crates
    cargo has downloaded but not yet unpacked.
    """
    member_suffix = f"{name}-{version}/Cargo.toml"
    for root in roots:
        tarball = root / f"{name}-{version}.crate"
        if not tarball.is_file():
            continue
        try:
            with tarfile.open(tarball, mode="r:gz") as tf:
                for member in tf:
                    if member.name == member_suffix:
                        fh = tf.extractfile(member)
                        if fh is None:
                            return None
                        with fh:
                            data = tomllib.loads(
                                fh.read().decode("utf-8", errors="replace")
                            )
                        pkg = data.get("package", {})
                        lic = pkg.get("license")
                        if isinstance(lic, str) and lic.strip():
                            return lic.strip()
                        if pkg.get("license-file"):
                            return "license-file:" + str(pkg["license-file"])
                        return None
        except (tarfile.TarError, OSError, tomllib.TOMLDecodeError):
            return None
    return None


def resolve_license(
    name: str,
    version: str,
    src_roots: list[Path],
    cache_roots: list[Path],
) -> tuple[str | None, str]:
    """Return (license, provenance). license is None only if no source knew it."""
    lic = license_from_registry_src(src_roots, name, version)
    if lic:
        return lic, "registry-src"
    lic = license_from_crate_tarball(cache_roots, name, version)
    if lic:
        return lic, "crate-tarball"
    return None, "none"


# ---------------------------------------------------------------------------
# SPDX expression evaluation
# ---------------------------------------------------------------------------

def _unwrap_groups(expr: str) -> str:
    return expr.replace("(", " ").replace(")", " ")


def _normalise_legacy_slash(expr: str) -> str:
    """`MIT/Apache-2.0` is SPDX 2.1's deprecated spelling of `MIT OR Apache-2.0`.

    Only a `/` between two identifier characters is a licence separator; SPDX ids
    never contain `/`, so this cannot damage any other token.
    """
    return re.sub(r"(?<=[A-Za-z0-9.\-])/(?=[A-Za-z0-9.\-])", " OR ", expr)


def _split_top(expr: str, op: str) -> list[str]:
    """Split on the `op` token at paren depth 0, dropping the operator itself.

    The operator token must not be glued onto either side, otherwise `A OR B`
    splits into ["A", "OR B"] and the right branch is never recognised.
    """
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for tok in expr.split():
        if depth == 0 and tok == op:
            parts.append(" ".join(cur))
            cur = []
            continue
        cur.append(tok)
        depth += tok.count("(") - tok.count(")")
    parts.append(" ".join(cur))
    return parts


def eval_license(expr: str, allow: set[str]) -> tuple[bool, list[str]]:
    """Evaluate one SPDX expression against the allow list.

    Returns (accepted, unallowed_ids_found) so a rejection explains itself.
    """
    work = _normalise_legacy_slash(_unwrap_groups(expr)).strip()
    unallowed: list[str] = []

    def walk(e: str) -> bool:
        e = e.strip()
        if not e:
            return False
        if " OR " in e:
            branches = _split_top(e, "OR")
            results = [walk(b) for b in branches]
            for b, ok in zip(branches, results):
                if not ok:
                    unallowed.append(b.strip())
            # A consumer may pick any branch, so one acceptable branch suffices.
            return any(results)
        if " AND " in e:
            terms = _split_top(e, "AND")
            results = [walk(t) for t in terms]
            for t, ok in zip(terms, results):
                if not ok:
                    unallowed.append(t.strip())
            return all(results)
        if e not in allow:
            unallowed.append(e)
            return False
        return True

    return walk(work), unallowed


def main() -> int:
    if not LOCK.exists():
        print(f"FAIL: {LOCK} not found; run a build to generate it")
        return 1

    src_roots = registry_src_roots()
    cache_roots = registry_cache_roots()
    if not src_roots and not cache_roots:
        print("FAIL: no cargo registry src and no registry cache (scanner is blind)")
        print("      run `cargo fetch` first")
        return 1

    allow = load_allow_list()
    packages = parse_lock(LOCK.read_text(encoding="utf-8"))
    if not packages:
        print("FAIL: Cargo.lock parsed to zero packages (scanner is blind)")
        return 1

    third_party = 0
    failures: list[str] = []
    counts: dict[str, int] = {}
    provenance: dict[str, int] = {}

    for name, version, source in packages:
        # No source => workspace member (first-party); its license is the project's own.
        if source is None:
            continue
        third_party += 1

        if source not in CRATES_IO_SOURCES:
            failures.append(f"FAIL: {name} {version}: source '{source}' is not crates.io")

        lic, where = resolve_license(name, version, src_roots, cache_roots)
        if lic is None:
            failures.append(
                f"FAIL: {name} {version}: license undeterminable "
                f"(not in any cargo home's registry src or .crate cache)"
            )
            continue
        provenance[where] = provenance.get(where, 0) + 1

        if lic.startswith("license-file:"):
            failures.append(
                f"FAIL: {name} {version}: declares license-file "
                f"({lic.split(':', 1)[1]}), not an SPDX expression"
            )
            continue

        counts[lic] = counts.get(lic, 0) + 1
        ok, unallowed = eval_license(lic, allow)
        if not ok:
            detail = ", ".join(sorted(set(unallowed))) or lic
            failures.append(
                f"FAIL: {name} {version}: license '{lic}' rejected; "
                f"no acceptable branch (rejected: {detail})"
            )

    if third_party == 0:
        print("FAIL: zero third-party packages scanned (scanner is blind)")
        return 1
    if not counts:
        print("FAIL: scanned packages but resolved zero licenses (scanner is blind)")
        return 1

    print(f"Cargo.lock: {len(packages)} packages, {third_party} third-party")
    print(
        "cargo homes: "
        + ", ".join(str(h) for h in cargo_homes())
        + f"\nlicense data: "
        + ", ".join(f"{n} from {src}" for src, n in sorted(provenance.items()))
    )
    print("licenses found:")
    for lic, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        ok, _ = eval_license(lic, allow)
        print(f"  [{'ok ' if ok else 'FAIL'}] {n:4d} x {lic}")

    if failures:
        print()
        for line in sorted(failures):
            print(line)
        print(f"\nLICENSE GATE: FAIL ({len(failures)} violation(s))")
        return 1

    print("\nLICENSE GATE: PASS")
    print(f"  licenses: all {third_party} third-party licenses satisfy schemas/deny.toml allow list")
    print("  sources:  all third-party packages from crates.io, no git sources")
    return 0


if __name__ == "__main__":
    sys.exit(main())
