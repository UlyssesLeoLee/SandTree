# SandTree — Agent 工作约定

## 项目定位

SandTree v1.1：Sandbox & Docker Control Plane（Windows 11 x64 baseline）。
统一管理 Docker Engine / Container / Compose、Windows Sandbox、Docker Sandbox、Multipass，
提供统一资源拓扑（Resource Graph）、统一 VFS（`stfs://`）、Snapshot/CAS、Plugin/App Cluster 与 Observation Plane。

设计基线（`Approved Design Baseline`，权威来源，本仓只读参考）：

| 文档 | 代码 | 用途 |
| --- | --- | --- |
| `01_Requirements_Definition.docx` | ST-V11-RD | FR-001..066 + FR-070..080 |
| `02_Nonfunctional_Requirements.docx` | ST-V11-NFR | NFR-A/P/O/M/S/E/U |
| `03_System_Architecture_Design.docx` | ST-V11-ARCH | Architecture View + ADR |
| `04_Basic_Design.docx` | ST-V11-BD | 画面/功能/接口/数据基本设计 |
| `05_Detailed_Design_Software.docx` | ST-V11-DD-SW | Rust workspace / Kernel / 算法 |
| `06_Detailed_Design_Plugin_Provider.docx` | ST-V11-DD-PLG | WIT / Docker / Sandbox / HotSwap |
| `07_Detailed_Design_Data_Interface.docx` | ST-V11-DD-DATA | SQLite / IPC / VFS / Event / Schema |
| `08_Detailed_Design_Security_Operations.docx` | ST-V11-DD-SECOPS | Threat / Policy / Runbook |
| `11_Detailed_Design_Observation_Plane.docx` | ST-V11-DD-OBS | Observation 详细设计 |

冲突优先级：v1.1 Observation 增量章节 > 前述 v1.0 基线章节。

机器可读契约（实现必须与之一致）：

- `schemas/001_init.sql` — Core SQLite DDL
- `schemas/error_codes.csv` — 稳定错误码 `ST-*`
- `schemas/observation_error_codes.csv` — Observation 错误码 `ST-OBS-*`
- `schemas/observation_provider_matrix.csv` — provider 观测模式矩阵
- `schemas/observation_snapshot_v1.schema.json` — ObservationSnapshot
- `schemas/plugin_manifest_v1.schema.json` / `app_manifest_v1.schema.json`
- `schemas/sandtree_provider_v1.wit` / `sandtree_observation_v1.wit` — 公共插件 ABI
- `schemas/workspace_uri_v1.md` — `stfs://` URI 规则
- `schemas/windows_probe_protocol_v1.md` — Windows Sandbox Probe 协议
- `schemas/deny.toml` — license/source gate
- `tests/test_cases.json` — 159 条测试用例

## Rust workspace 布局（DD-SW §1 / ARCH §11）

```
crates/{model,kernel,resource-graph,plugin-host,policy,event,store,vfs,ipc,sdk}
crates/{observation-model,observation-core}      # v1.1 增量
plugins/{provider-docker,provider-multipass,provider-windows-sandbox,provider-docker-sandbox,feature-compose}
plugins/{provider-git-remote,provider-mcp-remote}   # 向内网络取回（ADR-015），optional
apps/{daemon,cli,plugin-worker,probe-windows}
wit/                                             # ABI 源
tests/{contract,integration,system}
```

## 硬性不变量（违反即设计回退）

1. **Kernel 不得引用任何 provider SDK/厂商类型**（NFR-O02）。跨边界只走 domain DTO 或 WIT。
   `crates/kernel`、`crates/model`、`crates/resource-graph` 不得依赖 `bollard` / `wasmtime` / `rusqlite`。
2. **Observation 三平面分离**（ADR-OBS-001）。观测失败 ≠ 资源不存在；不得由 observation 失败推导 destroy/not-found。
3. **Trust 不提升**（ADR-OBS-003）。guest-probe 数据即使签名/哈希通过，trust 也固定 ≤ `guest_probe`。
4. **隔离不可交易**（NFR-S06/S07）。不得以暴露宿主 Docker socket、全盘可写映射、宿主管理员 token
   来换取观测能力；Probe bootstrap 只读，telemetry outbox 独立目录，Probe 无通用 shell。
5. **VFS 路径不得逃逸 root**（NFR-S05）。normalize 在 provider 调用前完成，mutation 前再做 canonical/symlink/reparse 检查。
6. **Capability deny-by-default**（NFR-S02）。插件 fs/network/exec/secret 默认拒绝，按 scope 授权。
7. **Snapshot 原子提交**（FR-044）。CAS object 先落盘、DB transaction 最后可见；失败不留半成品可见 snapshot。
8. **Plugin ABI 用 WASM Component Model + WIT**（ADR-002）。Rust dylib 不作为跨版本 ABI。
9. **Rust-first**（NFR-O03）。例外必须写 ADR。
10. **商业友好许可**（NFR-E03）。发布物仅允许 `schemas/deny.toml` 白名单；不捆绑付费/专有 runtime。
11. **禁止推测底层状态**（RD §9）。用户可见状态必须来自 provider/runtime/DB；不支持的字段显示 unavailable，不伪造。
12. **危险操作二次确认 + 审计**（NFR-U02）。

## 架构原则

- Microkernel 尽量小：Resource Graph / Plugin Host / Policy / Event / Store / VFS façade。
- 所有具体 runtime 以 plugin 隔离，API 变化被限制在 plugin 内。
- Lazy content：目录树只需 metadata；文件正文按需读；hash 仅在 mtime/size 变化或显式请求时计算。
- 事件带 `correlation_id` + `resource_id`；stream 统一支持 cancellation 与 backpressure。

## 构建与验证命令

```powershell
# 环境（Rust 不在 PATH，需要显式注入）
$env:RUSTUP_HOME="$env:USERPROFILE\.rustup"; $env:CARGO_HOME="$env:USERPROFILE\.cargo"
$env:PATH="$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin;$env:PATH"
# 或直接： .\scripts\dev.ps1 <cargo args>
```

质量门禁（缺一不可，全绿才算完成）：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check        # license/source/advisory gate
```

## 提交与文档

- 每个 crate 的改动须带 FR/NFR 追溯注释（`// FR-0xx` / `// NFR-xx`）。
- 需求语义变化必须同步 `traceability/*.csv` 与 `tests/test_cases.json`。
- 新增 ADR 追加到对应详细设计文档的 ADR 表，不新建游离文件。
- `E:\SandTree\*.docx` 为已批准设计基线，**只读**；实现偏差用 ADR 记录，不反向改设计书。