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
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check        # license/source/advisory gate
```

`--all-features` 不是可有可无的：

**feature-gated 的模块等于不在门禁里。** `wasmtime-abi` 关着的时候，
`crates/plugin-host/src/engine.rs`（整个 `ComponentGeneration` 适配器）和
`apps/plugin-worker` 的 `load()` 都**没有被编译过**，里面有真实缺陷——
`load` 在 arm 之前就调 guest，epoch 立即 trap，任何组件都装不上；
`Worker::load` 甚至编译不过。标准 `cargo test --workspace` 同样看不见它们，
而覆盖自检也看不见：`cargo test --list` 只列出**已编译**的测试，
所以「workspace owns N tests」这个集合已经把 feature-gated 的那部分
排除在外了——量具的输入集本身就是错的，红的和干净的长得一模一样。

因此：门禁必须带 `--all-features`；`mock/scripts/run_regression.ps1` 另有
`mock-engine` gate 显式编译 engine 语料，并断言它**至少跑了 1 条**测试
（编译了零个的 gate 比没有 gate 更糟）。

`--all-features` 只是两条正交轴里的一条。另一条是**出厂配置（default features）**：

**没有任何门禁覆盖「gate 外却依赖 gate 内符号」的代码。**
`apps/daemon/src/worker_client.rs` 无条件编译却引用了 `#[cfg(feature =
"in-process-worker")]` 门后的 `PackageSource`——`clippy --all-features` 全绿，
因为它把 gate 打开了，而 daemon 在出厂配置下根本编译不过。
只有 `it`/`st`/`uat` 三个 gate 同时 exit 101 撞见它，报的是症状不是病因。

因此：`run_regression.ps1` 有 **`default-build` gate**，用 `cargo metadata --no-deps`
查出所有声明了 optional 依赖的 crate，逐个 `cargo check -p <pkg> --offline`。
**一个 crate 一次调用**——cargo 在单次调用内跨包统一 feature，一次选四个包会通过
dev-dependency 把 gate 打开，于是「测着开了 gate 的构建、报告说测的是默认构建」。

模块边界跟着依赖边界走：`PackageSource` 不碰 wasmtime，就不该被装 wasmtime 的 gate 挡住
（`apps/daemon/src/packages.rs` 无门控，`loader.rs` 只剩 `WorkerLoader`）。

## 断言错误类别时，失败落点必须定死

「worker 死了」曾因**调度时序**报出两个码：写在已关闭 mailbox 上失败是 `ST-CORE-001`
（含义是「请求非法」），读到流结束是 `ST-PLG-002`。同一件事，两个分类。

写这个 bug 的测试自己踩了坑：`tokio::spawn(async move { drop(server); })` 让对端
**异步**消失，于是 `send` 和 `recv` 抢跑，测试每次都在赌它观察到哪一个。
变异验证时它**绿的**——缺陷存在，断言强度只有一半。

判据：断言「错误的类别」而不是「错误的内容」时，**把失败路径构造得唯一**。
`tokio::spawn(drop(peer))` 是竞态；`drop(peer)` 同步发生在返回前才是确定性路径。
`apps/daemon/src/worker_client.rs` 的 `transport_error()` 现在把 transport 层错误
一律归一到 `PLUGIN_HEALTH_FAILED`，原始码留在 message 里。

## 只测了错误分支的传输层，等于没测

`NamedPipeTransport` 把管道放在 `Arc` 里、用 `Arc::get_mut` 拿 `&mut`，而 mutex guard
仍持有引用，所以 **`get_mut` 永远返回 `None`**——连上之后每一次 `send`/`recv` 都失败。
它的测试只覆盖「未连接」那条路径，因为那是唯一不用真管道就能到的路径。
**这段代码从未搬运过一个字节。**

这是「feature-gated 等于不在门禁里」的同族第三例：那次是**零调用方**。
判据一样：**一条只有错误分支被测过的门禁，和一条什么都不测的门禁，在报告里长得一样。**
所以：任何传输/适配层必须有一条**成功路径**的测试，哪怕它只能跑在某个平台上；
`tests/system/tests/ipc_process.rs` 直接 spawn 真实二进制，因为只有子进程能抓住
「`main` 忘了调用它」——进程内测试永远抓不到。

## 假传输必须和真传输付同样的代价

`Loopback::recv` 返回带长度前缀的原始字节，`NamedPipeTransport::recv` 会解帧。
两者对「recv 返回什么」的说法不一致，于是**所有用 loopback 写的协议测试都在测一个
production 没有的契约**——而 loopback 的文档当时恰好写着「每个 test target 在测不同的东西」，
那句话是对的，只是没人把它当成对 loopback 的要求。

修法：分帧归 `Transport` 所有（`send(body)` 内部加帧，`recv` 返回 body），
调用方永远看不到前缀，于是**只有一个契约需要是对的**。
配套钉死一条：`recv_yields_the_body_not_the_framed_bytes`。

## 一个承诺了保证的名字，就是下一个人会依赖它的原因

`probe_pipe` 原本叫 `claim`：它建完管道实例立刻丢掉，什么都没持有，
但名字承诺了一个它不提供的独占性。改名是修法的一部分，不是文案。
同理：`test` 必须会失败而不是挂住——挂住的门禁拖垮整个 suite 而不是报告自己。

## 提交与文档

- 每个 crate 的改动须带 FR/NFR 追溯注释（`// FR-0xx` / `// NFR-xx`）。
- 需求语义变化必须同步 `traceability/*.csv` 与 `tests/test_cases.json`。
- 新增 ADR 追加到对应详细设计文档的 ADR 表，不新建游离文件。
- `E:\SandTree\*.docx` 为已批准设计基线，**只读**；实现偏差用 ADR 记录，不反向改设计书。