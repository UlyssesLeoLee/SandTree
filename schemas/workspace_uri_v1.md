# SandTree VFS URI v1

Canonical form: `stfs://<resource-id>/<absolute-within-root-path>`

Rules:
- resource-id is immutable within a discovery epoch and serialized as lower-case UUID/ULID-like opaque id.
- path separator is `/` in URI regardless of host OS.
- `.` is removed; `..` must never resolve above the declared workspace root.
- Windows drive/root details are provider metadata, not part of canonical URI.
- aliases such as `docker://...` may exist in UI, but storage/index/snapshot uses `stfs://`.
- symlink/reparse traversal is checked by provider before mutation.
