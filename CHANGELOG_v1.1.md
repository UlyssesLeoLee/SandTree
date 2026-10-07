# SandTree v1.1 — Observation Plane Baseline

- Formalized Control / Observation / Data Plane separation.
- Added Observation Strategy: Native → Exec → Probe → Metadata.
- Added ObservationSnapshot + Provenance/Trust/Freshness contracts.
- Added Docker Sandbox Native, Multipass Exec, Windows Sandbox disposable Probe design.
- Added lazy filesystem observation and Docker-in-Sandbox nested topology.
- Added FR-070..080 and NFR-A04/P05/P06/O05/S06/S07/S08/E05.
- Expanded test baseline from 134 to 159 cases.
- Agent/MCP/RAG remain optional integrations; Sandbox + Docker stay product core.
