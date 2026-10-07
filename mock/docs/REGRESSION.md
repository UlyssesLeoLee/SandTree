# SandTree 回归测试报告

- 运行标识：`20261008-084428`
- 设计用例：159 条（来自只读基线 `tests/test_cases.json`）
- 实际执行 Rust 测试：1196 条（通过 1195 / 失败 0 / 按设计挂起 1）

> 执行数按**去重后的测试名**统计，各 gate 汇报的 `test result: ok. N passed` 相加会略大于它：cargo 对集成测试只打印模块路径、不打印所属二进制，两个二进制里的同名测试在证据里会被并成一条。要按二进制区分，用 `mock/scripts/extract_test_inventory.py`。

## 四道 Gate 结果

| Gate | 用例数 | PASS | FAIL | PARTIAL | MANUAL | UNMAPPED |
| --- | --- | --- | --- | --- | --- | --- |
| UT | 50 | 48 | 0 | 1 | 0 | 1 |
| IT | 49 | 47 | 0 | 0 | 0 | 2 |
| ST | 37 | 34 | 0 | 0 | 0 | 3 |
| UAT | 23 | 0 | 0 | 0 | 23 | 0 |

## 状态含义

| 状态 | 含义 |
| --- | --- |
| `PASS` | 映射到的测试全部执行且通过 |
| `FAIL` | 至少一条映射测试执行且失败 |
| `PARTIAL` | 部分映射测试未找到（映射有笔误或测试被改名） |
| `MANUAL` | 该用例按设计需人工在真实环境验收；映射测试只覆盖机器可验部分 |
| `UNMAPPED` | 设计基线里有这条用例，但本仓没有任何验证 |

## 失败用例

无。

## 按设计挂起的测试

这些测试没有失败，是被 `#[ignore]` 主动移出默认门禁的（ADR-011：唯一依赖活 Docker daemon 的那条）。列出它们，是为了让「没跑」和「按设计不跑」在证据里不是同一件事。

- `provider::tests::health_reports_a_usable_engine_as_healthy`

## 未验证 / 待人工

| 用例 | 需求 | 标题 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `UT-018` | FR-054 | WIT descriptor validation | PARTIAL |  |
| `UT-025` | FR-023 | Operation cancellation | UNMAPPED | GAP: no cancellation test exists anywhere in the workspace. OperationState::Cancelled is declared and serialised |
| `IT-005` | FR-024 | Container log follow cancel | UNMAPPED | GAP: no cancellation test exists. Log follow cancel (FR-024) has no executable coverage at all. |
| `IT-008` | FR-027 | Volume in-use delete protection | UNMAPPED | GAP: no test covers in-use volume delete protection. provider.rs refuses prune outright but that is a different rule. |
| `ST-003` | NFR-P02 | Docker event UI latency | UNMAPPED | GAP: no event-to-UI latency measurement exists. There is no UI layer in this repo. |
| `ST-008` | FR-024 | Logs high volume | UNMAPPED | GAP: no log-volume test exists. FR-024 has no executable coverage. |
| `ST-026` | FR-060 | UI cognitive load | UNMAPPED | GAP: NFR/FR-060 UI cognitive load is not verifiable here. There is no UI layer; apps/desktop is not implemented. |
| `UAT-001` | AC-01 | See Docker + Sandbox tree | MANUAL | Machine-checkable: the tree is well-formed and deterministically ordered. "Clearly grouped" is a human judgement. |
| `UAT-002` | FR-011 | Start and stop sandbox | MANUAL | Machine-checkable: the verbs and the confirmation. "Intuitive" is a human judgement. |
| `UAT-003` | FR-014 | Browse sandbox files | MANUAL | Machine-checkable: canonical URI |
| `UAT-004` | FR-022 | Inspect containers | MANUAL | Machine-checkable: the fields are correct. "Details correct" in the UI is a human judgement. |
| `UAT-005` | FR-023 | Restart container | MANUAL | Machine-checkable: the operation runs and the terminal state persists. Status updating in the UI is a human judgement. |
| `UAT-006` | FR-024 | Read logs | MANUAL | GAP: FR-024 (read logs |
| `UAT-007` | FR-025 | Exec diagnostic command | MANUAL | Machine-checkable: output is bounded and returned. Audit linkage and "visible" are a human judgement. |
| `UAT-008` | FR-026 | Pull image | MANUAL | Machine-checkable: identity by digest. Progress reporting and the UI are a human judgement. |
| `UAT-009` | FR-027 | Protect in-use volume | MANUAL | GAP: in-use volume delete protection (FR-027) has no executable coverage. |
| `UAT-010` | FR-030 | Understand Compose project | MANUAL | Machine-checkable: the grouping is right. "Understand" is a human judgement. |
| `UAT-011` | FR-044 | Create snapshot | MANUAL | Machine-checkable: the snapshot is atomic and the manifest round-trips. |
| `UAT-012` | FR-044 | Compare snapshots | MANUAL | Machine-checkable: added/changed is reported. The diff view itself is a human judgement. |
| `UAT-013` | FR-050 | Install provider plugin | MANUAL |  |
| `UAT-014` | FR-052 | Upgrade plugin safely | MANUAL | Machine-checkable: rollback works and the new generation is active. "No loss" needs a real deployment. |
| `UAT-015` | FR-066 | Export diagnostic bundle | MANUAL | Machine-checkable: the bundle is deterministic and secret-free. |
| `UAT-016` | NFR-U01 | Default UI understandable | MANUAL | Not machine-checkable: default UI comprehensibility. There is no UI layer in this repo. |
| `UAT-017` | NFR-U02 | Dangerous actions clear | MANUAL | Machine-checkable: the refusal |
| `UAT-018` | NFR-E02 | Use non-Desktop Docker endpoint | MANUAL | Machine-checkable: a non-Desktop endpoint can be addressed and classified. |
| `UAT-019` | FR-062 | CLI fallback | MANUAL | Machine-checkable: CLI and daemon expose the same method set. |
| `UAT-020` | AC-07 | Release legal/OSS evidence | MANUAL | scripts/license_gate.py is the enforcing gate; these tests cover the in-process half. |
| `UAT-021` | FR-070 | Inspect sandbox internals consistently | MANUAL | Machine-checkable: the same domain set is reported consistently. "Same sections where supported" is a human judgement. |
| `UAT-022` | FR-076 | Understand trust and freshness | MANUAL | Machine-checkable: trust and freshness are reported and ordered. "Understandable" is a human judgement. |
| `UAT-023` | FR-079 | Understand degraded observation | MANUAL | Machine-checkable: the resource stays visible with a reason and a fallback. "Clearly shown" is a human judgement. |
