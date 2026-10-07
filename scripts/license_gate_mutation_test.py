"""Mutation check for scripts/license_gate.py.

A gate that cannot fail is indistinguishable from a gate that found nothing, so
this deliberately breaks the inputs and asserts the gate notices. Each mutation
is applied to a *copy* of the real files, the gate is run against them, the
original is restored from an in-memory snapshot, and the restore is verified by
sha256 before the next mutation starts.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENY = ROOT / "schemas" / "deny.toml"
LOCK = ROOT / "Cargo.lock"
GATE = ROOT / "scripts" / "license_gate.py"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run_gate() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE)], capture_output=True, text=True, cwd=str(ROOT)
    )
    return proc.returncode, proc.stdout + proc.stderr


def mutate_deny(old: str, new: str) -> bool:
    text = DENY.read_text(encoding="utf-8")
    if old not in text:
        return False
    DENY.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def mutate_lock_git_source() -> bool:
    text = LOCK.read_text(encoding="utf-8")
    needle = 'source = "registry+https://github.com/rust-lang/crates.io-index"'
    if needle not in text:
        return False
    LOCK.write_text(
        text.replace(needle, 'source = "git+https://example.invalid/evil.git?rev=x#deadbeef"', 1),
        encoding="utf-8",
    )
    return True


def main() -> int:
    deny_bytes = DENY.read_bytes()
    lock_bytes = LOCK.read_bytes()
    deny_sha, lock_sha = sha(DENY), sha(LOCK)

    def restore() -> None:
        DENY.write_bytes(deny_bytes)
        LOCK.write_bytes(lock_bytes)
        # Verify the restore rather than assuming it: a half-restored input would
        # silently poison every later run.
        assert sha(DENY) == deny_sha, "deny.toml restore FAILED (sha mismatch)"
        assert sha(LOCK) == lock_sha, "Cargo.lock restore FAILED (sha mismatch)"

    cases: list[tuple[str, object]] = [
        ("M1 MIT removed from deny.toml allow list", lambda: mutate_deny('"MIT",', '"MIT-removed",')),
        ("M2 a dependency source rewritten to a git URL", mutate_lock_git_source),
    ]

    failures: list[str] = []
    try:
        # Baseline: unmutated inputs must pass, otherwise "fails when mutated" is vacuous.
        rc, out = run_gate()
        if rc != 0:
            print("BASELINE FAILED - unmutated run did not pass:")
            print(out)
            return 1
        print("baseline PASS (expected)")

        for name, apply in cases:
            applied = apply()  # type: ignore[operator]
            if not applied:
                failures.append(f"{name}: mutation did not apply (input text changed)")
                restore()
                continue
            rc, out = run_gate()
            hits = [ln for ln in out.splitlines() if ln.startswith("FAIL:")]
            restore()
            if rc == 0:
                failures.append(f"{name}: gate still PASSED -> gate is vacuous for this case")
                print(f"[BAD ] {name}: gate PASSED (expected FAIL)")
            else:
                print(f"[GOOD] {name}: gate FAILed with {len(hits)} violation line(s)")
                for ln in hits[:3]:
                    print(f"         {ln}")
                if not hits:
                    failures.append(f"{name}: exit!=0 but no FAIL: line -> cannot confirm the rule")
    finally:
        restore()

    print(f"\ndeny.toml sha256   : {sha(DENY)}")
    print(f"Cargo.lock sha256  : {sha(LOCK)}")
    if failures:
        print("\nMUTATION CHECK: FAIL")
        for f in failures:
            print("  - " + f)
        return 1
    print("\nMUTATION CHECK: PASS (gate demonstrably fails on broken inputs; inputs restored)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
