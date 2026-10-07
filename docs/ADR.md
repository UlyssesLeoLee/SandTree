# SandTree v1.1 — 实现决策记录（ADR）

本文件记录**实现偏离设计基线之处**，以及实现过程中发现的、由测试或契约比对暴露的产品缺陷。

## 为什么 ADR 落在 `docs/` 而不是设计书

`AGENTS.md` 规定「新增 ADR 追加到对应详细设计文档的 ADR 表，不新建游离文件」。但设计基线
`00..11_*.docx` 是**只读**的已批准基线，实现不得反向改写。因此本文件作为**待并入的 ADR 集合**
存在：每条给出拟并入的目标文档与 ADR 表位置，供下一次受控的设计修订吸收。

## 状态

| ADR | 标题 | 拟并入 | 状态 |
| --- | --- | --- | --- |
| ADR-004 | 设计 WIT 无法严格解析，需本地副本 + 等价性测试 | DD-PLG §1 | 已实现 |
| ADR-005 | `wasmtime-abi` feature 默认关闭 | DD-SW §1 | 已实现，待评审 |
| ADR-006 | 审计 action 必须带资源命名空间（缺陷修复） | DD-SECOPS | 已实现 |
| ADR-007 | `tests/*` 由 `[lib]` 改为测试二进制 | ARCH §11 | 已实现 |
| ADR-008 | license 门禁的离线替代实现 | DD-SECOPS / 09 许可基线 | 已实现，待评审 |
| ADR-009 | 根 `workspace.dependencies` 的 bollard 版本回退到 0.18 | DD-SW §1 | 已实现 |

---

## ADR-004 设计 WIT 无法严格解析，需本地副本 + 等价性测试

**背景**　`schemas/sandtree_provider_v1.wit` 同时声明了 `record descriptor` 与
`descriptor: func()`。在严格 WIT 解析下这构成命名冲突，文件无法被解析，因此
`crates/plugin-host/src/engine.rs` 的 `bindgen!` 无法直接绑定设计文件。

**决策**　保留设计文件为唯一真源且**只读**；在 `crates/plugin-host/wit/` 放一份仅重命名字段
（`descriptor` → `descriptor-record`）的可解析副本，并加一条测试锁死两者的等价性
（`wit_copy_matches_design_file`）。任何一侧漂移都会让该测试变红。

**后果**　ABI 冻结点从「一个文件」变成「一个文件 + 一条等价性测试」。代价是多了一份需要同步的
副本，收益是设计基线保持只读、且漂移在 CI 可见。

**落点**　`crates/plugin-host/wit/sandtree_provider_v1.wit`、`crates/plugin-host/src/engine.rs`。

---

## ADR-005 `wasmtime-abi` feature 默认关闭

**背景**　设计要求 plugin-host 默认启用 Wasmtime 引擎。但本机 rustup shim 缺失、无 wasm32
target，默认开启会让 `cargo test --workspace` 在任何未 vendored 引擎的机器上直接失败。

**决策**　`wasmtime` 为 optional dependency，`wasmtime-abi` feature 默认 off；release 构建需显式
开启。`Cargo.toml` 中已注明原因。引擎相关测试在该 feature 下运行。

**后果**　`cargo test --workspace`（默认）不覆盖真实引擎路径。规避方式是 WAT 文本 fixture +
`mock/wasm-components` 的组件语料。

---

## ADR-006 审计 action 必须带资源命名空间

**背景（缺陷，非设计选择）**　`sandtree_policy::audit::AuditRecord::is_privileged()` 按
`action` 的命名空间前缀（`container.` / `sandbox.` / …）判定特权。而 `OperationManager::audit`
记录的 `action` 是裸动词 `req.op.as_str()`，例如 `destroy`。前缀永远匹配不上，
**`is_privileged()` 因此恒为 false，所有破坏性操作都被记为非特权**（违反 NFR-S03）。

该缺陷此前只有一个单测覆盖，而那个单测用的是 `"volume.remove"` 这种 kernel 从不产生的
命名空间 action —— 单测绿、集成路径死。

**决策**　`OperationManager::audit` 接收资源 kind，构造 `<kind>.<verb>` 作为 action；事件
payload 中的 `action` 与审计记录一致，两者不允许对「执行了什么」产生分歧。

**发现方式**　把 `tests/system` 里一条恒真断言 `assert!(audit >= 0)`（对 `usize` 恒成立）
换成真实断言（订阅事件总线、要求出现 `privileged: true` 的审计事件）后立刻变红。
详见 ADR-010。

**落点**　`crates/kernel/src/operations.rs`、`tests/system/tests/scenarios.rs`。

---

## ADR-007 `tests/*` 由 `[lib]` 改为测试二进制

**背景**　`tests/{contract,integration,system}` 原先声明为 `[lib]` crate。`cargo clippy
--workspace --all-targets` 会同时构建「非测试 lib」与「测试目标」两份，在非测试那份里
所有测试辅助类型（`Fake`、`World`、`Runtime`、`Stub`）及其方法都是死代码，产生约 15 条
结构性 `never used` 警告，淹没真实信号。

**决策**　改为常规 integration-test target：`tests/<name>/tests/scenarios.rs`，移除 `[lib]`。

**后果**　警告降到 0，且不再需要静音。测试辅助类型不再被 crate 外引用（此前也没有）。

---

## ADR-008 license 门禁的离线替代实现

**背景**　`cargo deny check` 是 NFR-E03 门禁，但本机无 `cargo-deny` 且无法联网安装。

**决策**　`scripts/license_gate.py` 做等价的 license + source 审计。

实现过程中踩到的三个坑值得记下来，因为它们每一个都会让门禁给出**错误但看起来合理**的结论：

1. **不能从 `Cargo.lock` 读 license。** 该文件根本没有 license 字段。照做会让 273 个包
   全部报「无法确定」—— 100% 假阳性。
2. **不能从 `registry/index/<i>/.cache/` 读。** 那是 cargo 的 sparse-index 缓存，
   实测不含 `license` 键（wasmtime 38.0.4 的条目以 `"v":2}` 结束，没有 license）。
3. **只能从 `registry/src/<n>-<v>/Cargo.toml` 或 `registry/cache/<i>/<n>-<v>.crate` 读**，
   后者是权威 tarball（sha256 被 Cargo.lock 固定），且覆盖「已下载未解包」的包。

此外 OR/AND 语义必须与 cargo-deny 一致：**OR 取任一分支可接受**，AND 需全部可接受，
`A/B` 视作 `A OR B`。把 OR 写成 AND 会让 `Unlicense OR MIT` 被误判为违规。

最后加自失效阈值（扫不到包 / 解析不出 license 直接 FAIL）与
`scripts/license_gate_mutation_test.py` 变异验证。

**未覆盖**　`cargo deny check advisories`（RustSec 数据库）仍需真实 cargo-deny。

---

## ADR-009 根 `workspace.dependencies` 的 bollard 版本回退

**背景**　根 `Cargo.toml` 声明 `bollard = "0.21"`，但 `Cargo.lock` pin 的是 0.18.1，且 0.21
未 vendored、离线取不到。`plugins/provider-docker` 因此绕开 workspace 依赖、自己声明
`bollard = "0.18"`。

**决策**　把 workspace 依赖改为 `bollard = "0.18"`，provider 改回 `bollard.workspace = true`。

**后果**　消除「谁写 `bollard.workspace = true` 就构建失败」的埋雷。代价是低于设计
假定的版本；如需 0.21，应在能联网的机器上升级 lock 后一并验证。

---

## ADR-010 清理恒真断言（缺陷，非设计选择）

**背景**　仓库自己的测试里存在 3 条恒真断言，它们长期「通过」而未验证任何东西：

| 位置 | 原断言 | 问题 |
| --- | --- | --- |
| `tests/system` | `assert!(audit >= 0)` | `usize` 与 0 比较恒真；且 `purge_events` 返回删除数，与「审计记录存在」无关 |
| `tests/integration` | `assert!(changed.is_empty() \|\| !changed.is_empty())` | 恒真 |
| `tests/integration` | `let changed: Vec<Change> = …;` 后无断言 | 空操作类型别名 |

**决策**　全部替换为真断言：审计改为订阅事件总线要求出现特权审计事件；stop 改为从
`OperationProgress` 事件取 operation_id 回查 store 的终态 job 行。

**后果**　替换后其中一条立即变红，牵出 ADR-006 的审计缺陷。这三条断言此前正好挡住了对
该缺陷的发现。

**规则**　新增测试禁止恒真断言（`assert!(x || !x)`、`assert!(n >= 0)` 等）；每条新断言须能
指出「若实现坏了，它会怎么红」。
