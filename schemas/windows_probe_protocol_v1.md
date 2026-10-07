# SandTree Windows Sandbox Probe Protocol v1

## Goal
Collect bounded telemetry from Windows Sandbox without turning the shared host filesystem into a general-purpose writable bridge.

## Bootstrap
- Probe binary and static config are exposed through a read-only mapped folder.
- Probe is launched by LogonCommand or explicit `wsb exec`.
- The probe is disposable and carries no long-lived secret.

## Output envelope
One snapshot per file, UTF-8 JSON, written as `<uuid>.part` and atomically renamed to `<uuid>.json`.
Required fields: `schema`, `sandbox_id`, `nonce`, `sequence`, `observed_at`, `domains`, `payload_hash`.

## Host validation
- filename and payload size limits
- schema version
- nonce/session binding
- monotonically increasing sequence per session
- timestamp skew and max age
- BLAKE3 payload hash
- JSON depth / array-size limits
- reject paths and filenames containing traversal components

## Security baseline
- Bootstrap mapping is read-only.
- Telemetry outbox is a dedicated empty directory and is never a source-code workspace.
- Host does not execute files written by the sandbox.
- Probe commands are fixed capabilities, not arbitrary shell.
- Any guest-reported value is tagged `guest_probe` trust.
