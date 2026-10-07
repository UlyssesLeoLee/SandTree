"""One-shot: bind each exported named type with an `eq` ascription.

A component may only export a function whose value types are named. Exporting a
type creates a *freshly aliased* type identity, so a function that keeps
referring to the original type id is not considered to be referring to a named
type. Ascribing the export as `(type (eq $t))` binds the exported name to the
existing type, which is what wit-component emits for every generated component.
"""

import pathlib
import re
import sys

FILES = [
    "fixtures/valid_provider_component.wat",
    "fixtures/wrong_package_name.wat",
    "fixtures/interface_version_mismatch.wat",
    "fixtures/missing_required_export.wat",
]

PATTERN = re.compile(r'^(\s*\(export "([a-z0-9-]+)" \(type \$([a-z0-9-]+)\)\)\s*)$', re.M)

root = pathlib.Path(sys.argv[1])
for rel in FILES:
    p = root / rel
    text = p.read_text(encoding="utf-8", newline="")
    new, n = PATTERN.subn(
        lambda m: f'{m.group(1)} (type (eq ${m.group(3)})))', text
    )
    p.write_text(new, encoding="utf-8", newline="")
    print(f"{rel}: ascribed {n} type exports")
