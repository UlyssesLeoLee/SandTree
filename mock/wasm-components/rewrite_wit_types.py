"""One-shot: export the named types *before* the instances that use them.

The validator registers an exported type into `exported_types` as it walks the
component's exports in order, and an instance export only validates if every
value type its functions mention is already in that set. Emitting the type
exports first is therefore required, not stylistic.
"""

import pathlib
import sys

BLOCK_START = "  ;; --- the named types the exported functions refer to ---"
FIRST_EXPORT = "\n  (export \""

FILES = [
    "fixtures/valid_provider_component.wat",
    "fixtures/wrong_package_name.wat",
    "fixtures/interface_version_mismatch.wat",
    "fixtures/missing_required_export.wat",
]

root = pathlib.Path(sys.argv[1])
for rel in FILES:
    p = root / rel
    text = p.read_text(encoding="utf-8", newline="")
    if BLOCK_START not in text:
        print(f"SKIP: {rel}")
        continue
    i = text.index(BLOCK_START)
    assert text.endswith(")\n"), rel
    j = len(text) - len(")\n")
    block = text[i:j]
    rest = text[:i].rstrip("\n") + "\n"
    k = rest.index(FIRST_EXPORT) + 1
    out = rest[:k] + block.rstrip("\n") + "\n\n" + rest[k:].lstrip("\n") + ")\n"
    p.write_text(out, encoding="utf-8", newline="")
    print(f"reordered: {rel}")
