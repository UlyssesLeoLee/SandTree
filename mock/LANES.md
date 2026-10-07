# SandTree Mock 项目 — Lane 契约（并行施工用）

本文件是 mock 项目三条并行 lane 的**唯一**边界与验收约定。派工前必须让每个子代理读完本文件。

## 背景：为什么需要 mock 项目

当前仓库有 4 个硬阻塞，使端到端回归无法在无真实 runtime 的环境下复现：

| 阻塞 | 证据 | 现状 |
| --- | --- | --- |
| 无 `wasm32-wasip2` target | rustup shim 缺失 | `plugin-host` 的 component 加载正向路径只能靠 WAT fixture |
| Docker daemon 状态不可控 | 子代理实测 daemon 在跑，但测试必须与它无关 | `provider-docker` 测试被迫注入不可达 endpoint |
| WSB / Multipass 无法在 CI 驱动 | — | 观测面完全无回归 |
| fake provider 在两个测试 crate 里各手写一份 | `tests/integration` 的 `Fake`（~700 行）、`tests/system` 的 `World`/`Runtime`（~500 行） | 重复且不可复用，改一处忘另一处 |

mock 项目的目标：**让全栈在零真实 runtime 下可跑、可回归**，并把上述重复收敛到一处。

## 目录约定（Ulysses 规则：测试脚本与测试数据归入 mock 项目）

```
mock/
  runtime/          # Lane A  —— 控制面 fake（ResourceProvider/FileProvider/ExecProvider）
  observation/      # Lane B  —— 观测面 fake（ObservationProvider + 故障注入）
  wasm-components/  # Lane C  —— WAT/wit 组件 fixture（绕开无 wasm32 target）
  fixtures/         # 三条 lane 共用的确定性 JSON fixture 语料
  README.md         # 如何新增一个世界 / 如何跑回归
  scripts/
    regression.sh   # 全量 mock 回归入口
```

`mock/*` 全部是 workspace member，因此 `cargo fmt/clippy/test --workspace` 自动覆盖它们，
**但它们不是产品代码**：不得被 `crates/*` 依赖，只允许 `tests/*` 与 `apps/*` 的 `dev-dependencies` 引用。

## 三条 lane（互不重叠，可真并行）

```
A runtime/  ─┐
B observation/ ─┼─> (合流后) tests/* 换用 mock + mock/scripts/regression.sh
C wasm-components/ ┘
```

### Lane A — `mock/runtime/`

**拥有（可写）**：`mock/runtime/**`、`mock/fixtures/runtime-*.json`
**禁止触碰**：其他所有路径，尤其 `tests/**`、`crates/**`、`Cargo.toml`（根）

交付：
1. `ScriptedWorld`：声明式 JSON 描述一个世界 —— resources / relations / 分页游标 / 每个操作的脚本化结果。
2. 实现 `sandtree_sdk::ports::{ResourceProvider, FileProvider, ExecProvider}`。
3. 确定性要求：无墙钟、无随机数、无环境探测；同一 fixture 两次运行产生完全相同的 `discover_all` 输出。
4. 支持故障注入：某操作失败、某资源不存在、分页中途出错、provider 整体不可用。
5. `#![deny(missing_docs)]`；每处实现带 `// FR-xxx` / `// NFR-xx` 追溯注释。
6. 集合序列化顺序确定（`BTreeMap` / 排序 `Vec`）。

验收：`cargo test -p sandtree-mock-runtime` 全绿 + `cargo clippy -p sandtree-mock-runtime --all-targets -- -D warnings` 无输出。

### Lane B — `mock/observation/`

**拥有（可写）**：`mock/observation/**`、`mock/fixtures/observation-*.json`
**禁止触碰**：其他所有路径

交付：
1. `ScriptedObservation`：实现 `ObservationProvider`，覆盖 `ObservationMode` × `TrustLevel` × `ObservationHealth` 的组合。
2. **ADR-OBS-001 形状**：观测失败必须返回 `Unavailable` 快照 + warning，**不得**返回 error，**不得**由观测失败推导资源不存在。
3. **ADR-OBS-003 形状**：`guest-probe` 永不升为 `host-native`；fixture 里出现升级企图时必须被拒绝。
4. 故障注入：deadline 超时、envelope 非法、部分域缺失、probe bootstrap 失败。
5. 禁止在 fixture 里放真实主机路径或凭据。

验收：`cargo test -p sandtree-mock-observation` 全绿 + clippy 干净。

### Lane C — `mock/wasm-components/`

**拥有（可写）**：`mock/wasm-components/**`（含 `fixtures/*.wat`）
**禁止触碰**：其他所有路径，尤其 `crates/plugin-host/**`

交付：
1. 手工编写的 WAT 文本组件 fixture，覆盖：合法组件、包名错误、缺失 export、接口版本不匹配。
2. 每个 fixture 一个 `.wat` 文件 + 一个 Rust 常量字符串，**不依赖 wasm32 target**。
3. 一份 `MANIFEST.json` 列出每个 fixture 的意图与预期结果，供 host 侧测试驱动。
4. 锁死 ADR-004：`schemas/sandtree_provider_v1.wit` 与 `crates/plugin-host/wit/sandtree_provider_v1.wit` 的等价性，
   由 Lane C 提供 fixture，C 侧**不得**修改 `crates/plugin-host` 的任何文件。

验收：`cargo test -p sandtree-mock-wasm-components` 全绿 + clippy 干净。

## 三条 lane 共同的硬规则

1. **不改根 `Cargo.toml`。** workspace member 注册由集成阶段（主线）统一做，否则三条 lane 会互相冲突。
2. **不碰 `tests/**`、`crates/**`、`apps/**`、`plugins/**`。** 需要这些文件改动时，把需求写进 handoff 报告，由主线执行。
3. **自带 checkpoint commit**：每完成一个可编译的逻辑单元就 commit 一次，commit message 用
   `mock/<lane>: <做了什么>`。子代理通道不稳定，断线时磁盘上的 commit 不会丢 —— 本轮已有先例
   （provider-docker / provider-multipass 在子代理断线后仍完整留在磁盘上并通过门禁）。
4. **不改设计基线**：`E:\SandTree\*.docx`、`schemas/*`、`tests/test_cases.json` 只读。偏差写 ADR 报告，不改文件。
5. **不留真空断言**：禁止 `assert!(x || !x)`、`assert!(n >= 0)` 这类恒真断言。本轮已在
   `tests/integration` 和 `tests/system` 抓到 3 条这种断言，它们伪装成测试但什么都没验。
6. **门禁自证**：每条 lane 交付前必须跑一次变异验证，确认自己的测试在实现被破坏时真的会红。

## 交付 handoff 格式

```
Lane:            A | B | C
Branch/Worktree: agent/<lane>-<name>
Base branch/SHA: dev@<sha>
Commits:         <sha> <sha> ...
Files changed:   <...>
Tests:           <命令> -> <结果>
Mutation proof:  <变异了什么> -> <测试是否变红>
Needs from main: <需要主线改的文件清单，若无则写 none>
```

## 集成顺序（主线执行，不是 lane 的事）

1. 主线把三条 lane 的 crate 注册进根 `Cargo.toml` workspace members。
2. 主线逐条 `git rebase agent/<lane> dev`，冲突在 lane 内解决。
3. 主线串行 merge 进 `dev`（一次一条，保护集成分支不被并行写）。
4. 合并后重跑全量门禁；全绿才算 INTEGRATED。
5. 最后由主线把 `tests/integration` 的 `Fake` / `tests/system` 的 `World` 换成 mock 引用（D lane 的工作，依赖 A/B/C 全部就位）。
