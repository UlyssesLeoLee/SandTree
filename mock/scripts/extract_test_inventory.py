#!/usr/bin/env python3
"""Extract the workspace test inventory with each test attributed to its crate.

`cargo test -- --list` prints two interleaved kinds of line:

    Running unittests src\\lib.rs (…\\deps\\sandtree_vfs-2f4a….exe)   <- a target banner
    confinement::tests::confine_joins_within_root: test               <- one test

The test line alone is not enough to identify a test: an integration test binary
prints bare names, and two binaries can print the same name. Worse, every lib
target prints the *same* banner text ("unittests src\\lib.rs") — the crate is
only in the path cargo appends. Any mapping from a design case to a test that
ignores that path will silently attribute tests to the wrong crate.

Output: TSV with columns crate, kind, name.
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

BANNER = re.compile(r"^\s*(?:Running|Doc-tests)\s+(?P<desc>.+?)\s*(?:\((?P<exe>.+)\))?\s*$")
LISTED = re.compile(r"^(?P<name>.+?): test$")
# cargo names the binary <crate_name>-<16 hex>.exe
EXE = re.compile(r"deps[\\/](?P<crate>[A-Za-z0-9_]+)-(?P<hash>[0-9a-f]{16})\.exe$")


def classify(desc: str, exe: str | None) -> tuple[str, str]:
    """Return (kind, identity).

    `identity` is the binary stem including cargo's hash. That is deliberate:
    contract/integration/system all live in a file called `tests/scenarios.rs`,
    so the bare name "scenarios" identifies three different binaries and would
    merge their tests into one indistinguishable bucket.
    """
    d = desc.strip()
    m = EXE.search(exe or "") if exe else None
    if d.startswith("Doc-tests"):
        return "doctest", m.group("crate") if m else d
    if m:
        return "binary", f"{m.group('crate')}#{m.group('hash')}"
    m2 = re.search(r"(?:unittests\s+)?(?P<file>[\w.]+\.rs)$", d)
    if m2:
        return "target", m2.group("file")
    return "target", d


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: extract_test_inventory.py <cargo-test-list.log> [out.tsv]", file=sys.stderr)
        return 2
    log = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else log.with_suffix(".tsv")

    rows: list[tuple[str, str, str]] = []
    current = ("(none)", "unknown")  # (kind, crate)
    for raw in log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        m = LISTED.match(line)
        if m:
            # classify returns (kind, crate); the TSV column order is
            # (crate, kind, name), so the pair is transposed here rather than
            # being silently written in the wrong order.
            rows.append((current[1], current[0], m.group("name").strip()))
            continue
        m = BANNER.match(line)
        if m:
            current = classify(m.group("desc"), m.group("exe"))

    body = ["crate\tkind\tname\n"]
    body += [f"{c}\t{k}\t{n}\n" for c, k, n in sorted(set(rows))]
    out.write_text("".join(body), encoding="utf-8")

    per = collections.Counter(c for c, _, _ in rows)
    print(f"tests: {len(rows)}  unique: {len({r[2] for r in rows})}  crates: {len(per)}")
    for crate, n in per.most_common():
        print(f"  {n:4d}  {crate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
