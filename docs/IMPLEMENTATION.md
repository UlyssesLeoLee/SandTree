# SandTree v1.1 实现说明（IMPL）

本文件描述**代码实现**如何落地已批准设计基线。设计基线文档（`*.docx`）只读；本文件不替代设计，只记录实现选择与偏差。

## 1. 构建

```powershell
# 推荐
.\scripts\dev.ps1 gate          # fmt + clippy + test
.\scripts\dev.ps1 build --release

# 或手动（cargo 不在本机 PATH）
$env:PATH="$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin;$env:PATH"
$env:CARGO_HOME="$env:USERPROFILE\.cargo"
cargo test --workspace
```

本机环境事实（实现时验证）：

| 项 | 状态 |
| --- | --- |
| Rust | 1.98-x86_64-pc-windows-msvc（toolchain 在 `%USERPROFILE%\.rustup\toolchains`，rustup shim 缺失，故走 `scripts/dev.ps1`） |
| MSVC | VS 2022 Community 14.44，`cl.exe`/`link.exe` 可用 |
| cargo-deny / cargo-about | 需 `cargo install`，CI 中安装 |
| Docker | CLI 存在（Docker Desktop）；本机 daemon 未运行 ⇒ provider 必须降级为 `Unavailable` 而不是报错阻塞（FR-001/NFR-A01 的真实演练） |
| Multipass | CLI 存在 |
| Windows Sandbox | `wsb.exe` 存在 |

> Docker daemon 未运行这件事本身被当作验收场景使用：`sandtree` 必须在只有部分 provider 可用时仍能启动并给出可诊断的健康状态。

## 2. crate 与职责

| crate | 职责 | 禁止依赖 |
| --- | --- | --- |
| `model` | ResourceNode/Relation/Capability/Operation/Event/ErrorCode | 一切 provider SDK、SQLite、Wasmtime |
| `observation-model` | Mode/Trust/Health/Provenance/Snapshot/Plan/FileMetadata | 同上 |
| `vfs` | `stfs://` 解析、路径归一、root 逃逸防护、mount 注册表、read 配额 | IO、async |
| `policy` | capability 决策（deny-by-default）、脱敏、审计、trust 门禁 | IO、async |
| `event` | 类型化事件路由、有界队列、背压合并 | IO |
| `resource-graph` | 内存拓扑树 + 关系索引 + stale/tombstone 生命周期 | IO、async |
| `store` | SQLite repositories、CAS、migration、retention | provider SDK |
| `observation-core` | 策略协商、调度合并、缓存/freshness、归一化与限额 | provider SDK |
| `sdk` | plugin/app manifest + provider ports（公共 ABI 的 Rust 侧类型） | Wasmtime |
| `plugin-host` | Wasmtime Component Model、generation 路由、hot swap | — |
| `kernel` | PluginSupervisor/ResourceManager/OperationManager/WorkspaceManager/SnapshotManager/EventRouter/StoreManager | provider SDK、rusqlite（经 port） |
| `ipc` | 帧编解码、方法路由、named pipe 传输 | — |

依赖方向与 API 冻结在 `docs/CONTRACTS.md`。

## 3. 关键实现决策

1. **Observation 失败不是错误**：`ObservationSnapshot::empty(..., health=Unavailable)` 是合法返回值；
   只有协议/安全违规（如 probe envelope 非法）才产生 `DomainError`（ADR-OBS-001）。
2. **Trust 不提升**：`Provenance::with_evidence` 只加 hash，不改 `trust`；
   快照整体可信度取 `weakest_trust()`（ADR-OBS-003）。
3. **destructive precondition 需要 host 级可信数据**：`TrustPolicy` 默认要求
   `TrustLevel::HostNative`，`guest_probe` 一律拒绝并返回 `ST-OBS-009`。
4. **stale ≠ 不存在**：reconcile 先 `Unknown`，超过 grace 才 `Tombstoned`；
   单轮未发现不会删除资源。
5. **VFS 双重检查**：路由前 normalize（`vfs`），mutation 前 provider 内再 canonicalize
   （处理 symlink/reparse），两道都必须过。
6. **事件背压**：慢订阅者队列满时合并 `ResourceChanged`，保留 audit/error 事件，
   并累加 `LagSignal`。
7. **CAS 先于可见性**：snapshot 对象先落盘（temp → rename），DB transaction 最后提交；
   失败不留半成品可见 snapshot（FR-044）。孤立对象由 GC 标记扫描回收。
8. **Hash 惰性**：`ContentHashState` 四态；只有 mtime/size 变化、snapshot、diff
   或显式请求才计算 BLAKE3（FR-077）。

## 4. 未在本仓实现的部分（及原因）

| 项 | 原因 | 影响 |
| --- | --- | --- |
| `apps/desktop`（Tauri 2 GUI） | 需要完整前端工具链与 WebView2 打包流程，构建体量与验证成本远超本轮；FR-060 的 UI 契约已由 `ipc` 方法族与 CLI 覆盖 | UI 需后续补齐；kernel/CLI 契约不变 |
| `optional/{search-tantivy, git-gix, integration-mcp, agent-observer}` | 设计中明确为 OPTIONAL，且 FR-O01/FR-O02 不属于核心 | 无功能影响 |
| `Docker Sandboxes` 实验 API 的真实联调 | 该 API 为 experimental，且本机 Docker daemon 未运行 | provider 以 schema adapter + capability probe 实现，失败回退 metadata-only（DD-PLG §12.2 已规定） |
| wasm 组件示例插件（.wasm 产物） | 本机无 rustup shim，无法安装 `wasm32-wasip2` target 交叉编译 | `plugin-host` 的 component 加载路径用 fixture/错误路径测试覆盖；ABI 由 `wit/` 与 `schemas/*.wit` 冻结 |

## 5. 测试分层（对齐 ARCH §11 / tests/）

| 层 | 位置 | 内容 |
| --- | --- | --- |
| UT | 各 crate 内 `#[cfg(test)]` | 纯算法：URI、capability、reconcile、trust、framing、envelope 限额 |
| Contract | `tests/contract` | manifest 校验、WIT 契约字段、错误码注册表、schema 一致性 |
| Integration | `tests/integration` | 真实 provider（Docker/Multipass/WSB）+ 内存 store + fake clock |
| System | `tests/system` | daemon + IPC + CLI 端到端，多 provider 降级场景 |

## 6. 追溯

`traceability/requirements_to_tests.csv` 记录 FR/NFR → 测试 ID 映射；
新增实现必须补一行映射，并在代码中以 `// FR-xxx` / `// NFR-xx` 标注落点。