# SandTree mock 项目

三个 mock crate，让全栈在**零真实 runtime**（无 Docker、无 Multipass、无 Windows Sandbox、
无可交叉编译的 wasm32 target）的机器上可跑回归。

它们是 workspace member，所以 `cargo fmt/clippy/test --workspace` 自动覆盖；
但**不是产品代码**：`crates/*` 不得依赖它们，只允许 `tests/*` 与 `apps/*`
以 `dev-dependencies` 引用。这条边界由 mock 契约与
`tests/contract` 的检查共同维持。

| crate | 面向 | 钉住的不变量 |
| --- | --- | --- |
| `mock/runtime` | 控制面：`ResourceProvider` / `FileProvider` / `ExecProvider` + fleet 扫描 | FR-001 分页、FR-013 exec 预算、FR-023/027 破坏性操作确认、FR-051 能力上限、FR-061、**NFR-S05** 路径不得逃逸 root、**NFR-O04** 确定性 |
| `mock/observation` | 观测面：`ObservationProvider` + 故障注入 | **ADR-OBS-001** 观测失败 ≠ 资源不存在、**ADR-OBS-003** Trust 永不提升、FR-079/077 |
| `mock/wasm-components` | 插件 ABI：手写 WAT 组件语料 | **ADR-004** 两份 WIT 等价、**ADR-002** Component Model ABI、FR-054 |

`fixtures/` 存放跨 crate 共用的确定性 JSON 语料。

## 为什么是 mock，而不是在测试里现写 fake

本仓原有两份手写 fake（`tests/integration` 的 `Fake` ~700 行、
`tests/system` 的 `World`/`Runtime` ~500 行），重复且改一处容易忘另一处。
把它们收敛到一处并做成 workspace crate，是这个项目的主要收益。

> **待办**：`tests/integration` 与 `tests/system` 目前仍在使用自己那份 fake。
> 迁移到 mock crate 引用是下一阶段的工作，届时上面两份重复可以删除。

## 确定性契约

三个 crate 共同遵守：**无墙钟、无随机数、无环境探测**。同一 fixture 两次运行
必须产生逐字节相同的输出（`mock/runtime` 有专门测试锁死这一点）。
任何「因为跑了两次不一样所以是并发问题」的怀疑，都应该先来这里核对。

因此 fixture 里禁止出现真实主机路径、凭据或密钥。
`mock/observation` 有一个卫生扫描器会因此让构建失败。

## 怎么用

### 加载一个内置世界

```rust
use sandtree_mock_runtime::{fixtures, ScriptedWorld};

// docker 形状的健康世界：分页发现、脚本化操作、文件、exec 规则
let world = ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD)?;

// 三个 port 共享同一个 world
let instance = world.into_shared().provider_instance();
let resources = instance.resource;   // ResourceProvider
let files     = instance.files;      // FileProvider
let exec      = instance.exec;       // ExecProvider
```

内置语料清单见 `mock/runtime/src/fixtures.rs::all()`：
`docker-world` / `unavailable-world` / `mid-page-failure-world` /
`failing-operations-world` / `escaping-symlink-world` / `large-output-world`。

### 新增一个世界

往 `mock/runtime/src/fixtures.rs` 加一个 `pub const XXX_WORLD: &str`，用
`ScriptedWorld::from_json_str` 加载即可。加载器会拒绝：

- 重复 key / 两个 key 派生同一个 id
- 悬空 parent / parent 成环
- 未知 error code（必须来自 `schemas/error_codes.csv`）
- 目录声明 content、symlink 同时声明 body
- `files[].root` 指向不存在的资源
- 时间戳不可解析

写完之后把它加进 `all()`，那条「所有内置世界都能加载」的测试会自动覆盖它。

### 观测面

`mock/fixtures/observation-scenarios.json` 是 12 个 world，覆盖
4 种 `ObservationMode` × 4 档 `TrustLevel` × 3 种 `ObservationHealth`，
外加部分域缺失、withheld domain、协议/安全故障、deadline 超时。

`mock/observation/tests/adr_obs_003.rs` 里的 mode→trust 上限表是**字面量写死的**，
不从实现反推 —— 否则实现改了断言也不会红，而那正是 ADR-OBS-003 禁止的变异。

### 组件语料

`mock/wasm-components/fixtures/*.wat` 是手写 WebAssembly 文本。
本机没有 `wasm32-wasip2` target，无法交叉编译 guest；但 wasmtime 的
文本格式解析器是 host-target 的，不需要 guest 工具链，所以把 WAT 直接
喂给引擎走的是同一条 compile → instantiate → link 路径。

`MANIFEST.json` 声明 host 对每个 fixture 必须做什么，测试会证明
manifest、fixture 与冻结的 WIT 三者一致 —— 包括「派生的 fixture 只在它
声明的那几行上与合法 fixture 不同」，所以一次拒绝可以归因到具体规则。

引擎相关的检查在默认关闭的 `engine` feature 后面：

```powershell
cargo test -p sandtree-mock-wasm-components --features engine
```

## 门禁

与其他 crate 同一套，没有豁免：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test --workspace --offline
python scripts/license_gate.py
```

全仓唯一一条需要活的 Docker daemon 的测试是
`provider-docker` 的 `health_reports_a_usable_engine_as_healthy`，
已标 `#[ignore]`，在 daemon 起来的机器上用
`cargo test --workspace -- --ignored` 跑。
**mock 项目自身没有任何一条测试依赖外部 runtime。**
