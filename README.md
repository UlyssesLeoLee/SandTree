# SandTree v1.1 — Sandbox & Docker Control Plane

Current baseline: **v1.1 Observation Plane**.

SandTree manages sandboxes and Docker runtimes as a unified resource topology. v1.1 formalizes how SandTree observes isolated environments without defeating their isolation boundaries.

Core planes:
- Control Plane — lifecycle / exec / mutations
- Observation Plane — state / process / filesystem / network / nested Docker
- Data Plane — VFS / logs / snapshot / CAS / indexes

Observation modes: **Native → Exec → Probe → Metadata**. Every observed value carries provenance, trust and freshness.

See `11_Detailed_Design_Observation_Plane.docx` for the authoritative detailed design.
