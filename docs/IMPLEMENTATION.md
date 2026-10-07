# SandTree v1.1 实现说明（IMPL）

本文件描述**代码实现**如何落地已批准设计基线。设计基线文档（`*.docx`）只读；本文件不替代设计，只记录实现选择与偏差。

偏差的正式记录见 [`ADR.md`](ADR.md)。

## 1. 构建

```powershell
# 推荐
.\scripts\dev.ps1 gate          # fmt + clippy + test
.\scripts\dev.ps1 build --release

# 或手动（cargo 不在本机 PATH）
$env:PATH="$env:USERPROFILE\.rustup\toolchains\1.98-x86_64-pc-windows-msvc\bin;$env:PATH"
$env:CARGO_HOME="E:\DevCache\cargo"
cargo test --workspace --offline
```

质量门禁（缺一不可）：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test --workspace --offline
python scripts\license_gate.py          # cargo deny 的离线等价物，见 §6
```

本机环境事实（实现时验证）：

| 项 | 状态 |
| --- | --- |
| Rust | 1.98-x86_64-pc-windows-msvc（toolchain 在 `%USERPROFILE%\.rustup\toolchains`，rustup shim 缺失，故走 `scripts/dev.ps1`） |
| MSVC | VS 2022 Community 14.44，`cl.exe`/`link.exe` 可用 |
| `CARGO_HOME` | `E:\DevCache\cargo`（本地盘）；`%USERPROFILE%\.cargo` 另有一份，历史依赖在那边，license 门禁两处都扫 |
| `CARGO_TARGET_DIR` | `E:\DevCache\cargo\target`（仓库外）。**多 worktree 并行时必须按 lane 分目录**，否则 cargo 包缓存锁会让并行构建退化成串行 |
| cargo-deny / cargo-about | **未安装**，本机无法执行；由 `scripts/license_gate.py` 离线替代（见 §6） |
| Docker | CLI + daemon 均可用（server 29.8.2）。但 provider 测试**必须与 daemon 状态无关**，因此一律走 fixture 或注入不可达 endpoint |
| Multipass / Windows Sandbox | CLI / `wsb.exe` 存在，但无法在 CI 驱动 → 观测面无真实联调，由 mock 项目覆盖 |
| wasm32 target | **无法安装**（无 rustup shim）→ 不能交叉编译真实 `.wasm`；`plugin-host` 的 component 加载路径由 WAT fixture 覆盖 |

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
| `plugin-host` | Wasmtime Component Model、generation 路由、hot swap、install policy、worker limits | — |
| `kernel` | PluginSupervisor/ResourceManager/OperationManager/WorkspaceManager/SnapshotManager/EventRouter/StoreManager | provider SDK、rusqlite（经 port） |
| `ipc` | 帧编解码、方法路由、named pipe 传输 | — |
| `plugin-host`/`wit/` | ADR-004 的本地 WIT 副本 | — |

provider（实现 `sdk` ports）：

| crate | 设计依据 | 关键形状 |
| --- | --- | --- |
| `plugins/provider-docker` | DD-PLG §5 | bollard 0.18；endpoint 解析；host policy 拒绝危险路径 |
| `plugins/provider-multipass` | DD-PLG §9 | `multipass list/info --format json` + `exec`；CLI 缺失 → `Unavailable` 而非空 batch |
| `plugins/provider-windows-sandbox` | DD-PLG §7 / §12.4 | `.wsb` 解析 + probe envelope 校验；bootstrap 只读、映射限 outbox |
| `plugins/provider-docker-sandbox` | DD-PLG §8 / §12.2 | 三级降级 API → CLI → fixture；所有 tier 的 trust 均为 `guest_probe` |
| `plugins/feature-compose` | DD-PLG §6 / FR-030..032 | 消费 Docker provider 已有的 label 分组；生命周期经注入的 `ComposeRunner` |

apps：`daemon`（IPC 服务 + EventPump + `--check` 自检）、`cli`、`plugin-worker`、`probe-windows`。

依赖方向与 API 冻结在 `docs/CONTRACTS.md`。

## 3. 关键实现决策

1. **Observation 失败不是错误**：`ObservationSnapshot::empty(..., health=Unavailable)` 是合法返回值；
   只有协议/安全违规（如 probe envelope 非法）才产生 `DomainError`（ADR-OBS-001）。
2. **Trust 不提升**：`Provenance::with_evidence` 只加 hash，不改 `trust`；
   快照整体可信度取 `weakest_trust()`（ADR-OBS-003）。`TrustLevel` 的派生 `Ord` 与信任强度**方向相反**
   （枚举按展示序声明，最强在前），任何信任推理必须走 `TrustLevel::rank()` / `at_most()`。
3. **destructive precondition 需要 host 级可信数据**：`TrustPolicy` 默认要求
   `TrustLevel::HostNative`，`guest_probe` 一律拒绝并返回 `ST-OBS-009`。
4. **stale ≠ 不存在**：reconcile **先删（基于上一轮 stale 状态）后扫**（DD-SW §5），保证
   `unknown` 至少可见一轮；`mark_resources_stale` 用 provider **本轮实际返回**的 seen 集合，
   绝不从 DB 回读，否则「provider 停止上报」永不生效。
5. **VFS 双重检查**：路由前 normalize（`vfs`），mutation 前 provider 内再 canonicalize
   （处理 symlink/reparse），两道都必须过。
6. **事件背压**：慢订阅者队列满时合并 `ResourceChanged`，保留 audit/error 事件，
   并累加 `LagSignal`。
7. **CAS 先于可见性**：snapshot 对象先落盘（temp → rename），DB transaction 最后提交；
   失败不留半成品可见 snapshot（FR-044）。孤立对象由 GC 标记扫描回收。
8. **Hash 惰性**：`ContentHashState` 四态；只有 mtime/size 变化、snapshot、diff
   或显式请求才计算 BLAKE3（FR-077）。
9. **审计 action 必须带命名空间**：`AuditRecord::is_privileged()` 按 `<kind>.<verb>` 的
   namespace 判定。记录裸动词（`destroy`）会让**所有**破坏性操作被标成非特权（NFR-S03）。
10. **CLI 缺失是降级不是消失**：compose 在无 CLI 时报 `Degraded` 而非 `Unavailable`
    （FR-031 是 SHOULD，发现能力必须存活）；docker-sandbox 在无 API 无 CLI 时走 fixture tier，
    仍能 `discover`。

## 4. 测试分层（对齐 ARCH §11 / tests/）

| 层 | 位置 | 内容 |
| --- | --- | --- |
| UT | 各 crate 内 `#[cfg(test)]` | 纯算法：URI、capability、reconcile、trust、framing、envelope 限额 |
| Contract | `tests/contract/tests/scenarios.rs` | 错误码双注册表、WIT 包名、manifest/DDL 与代码一致性、wire 名 |
| Integration | `tests/integration/tests/scenarios.rs` | 跨 crate 流程，provider 为 fake |
| System | `tests/system/tests/scenarios.rs` | 破坏性操作确认+审计、观测信任不上升、IPC 抗截断 |
| Mock | `mock/**`（并行 lane 产出，见 `mock/LANES.md`） | 全栈在零真实 runtime 下可回归 |

`tests/{contract,integration,system}` 是**测试二进制**而非 library。这不是风格问题：
声明为 `[lib]` 时 `cargo clippy --all-targets` 会同时构建「非测试 lib」和「测试目标」两份，
于是所有测试辅助类型在 lib 那份里都是死代码，门禁被结构性噪声淹没。

### 反真空断言

本轮从仓库自己的测试里清掉 3 条恒真断言（`assert!(n >= 0)`、`assert!(x || !x)`）。
把它们换成真断言后，其中一条立刻变红，并牵出上面第 9 条的审计缺陷 —— 说明它们一直在
「通过」的同时什么都没验。**新增测试禁止恒真断言**。

## 5. mock 项目

三个 mock crate 已合入 `dev`，让全栈在零真实 runtime 下可跑回归。
详见 `mock/README.md`（面向使用者）。本节只记录**本轮为此改动了什么**。

| crate | 解决的问题 | 测试数 |
| --- | --- | --- |
| `mock/runtime` | 收敛 `tests/integration` 的 `Fake` 与 `tests/system` 的 `World` 两份重复 fake | 77 |
| `mock/observation` | 观测面零回归：ADR-OBS-001 / ADR-OBS-003 的故障注入 | 81 |
| `mock/wasm-components` | 无 wasm32 target → WAT fixture 覆盖 component 加载路径 | 24 |

三条 mock crate 由三条 git worktree lane 并行产出，各自独立 `CARGO_TARGET_DIR`
（共享目录会让 4 个 cargo 进程抢同一把包缓存锁，并行退化为串行），
逐条 rebase 后串行 merge 进 `dev`。脚手架（lane 驱动脚本、临时 runner）
未随代码进仓。

**并行产出必须由门禁裁决，不由子代理的「完成」声明裁决。** 本轮三个 lane
交付的代码在第一次跑门禁时全部是红的，其中隐藏的缺陷包括：

- `discover_all` 无法终止：provider 用 `cursor: None` 表示扫描结束时循环没有退出分支，
  而 `None` 同时是扫描的起始游标，于是从第一页重新开始无限翻页，堆到分配器失败（288MB）。
  模块文档当时已经承诺「loop cannot hang」。
- symlink 解析把 base 目录算了两遍，`workspace/app/ok.txt` 解析成 `workspace/workspace/app/ok.txt`。
- 工作区根目录无法列举：根条目 `parent_path()` 是 `None` 而过滤条件问的是 `Some("")`，
  于是列根返回空、列任何子目录都正常。
- 三个校验 fixture 生成了重复 JSON key，测试断言的是解析错误而不是它们名字里的那条规则。
- `LARGE_OUTPUT_WORLD` 声明 176 字节而 cap 是 4096，截断测试什么都没验。
- `mock/wasm-components` 根本没编译过：漏声明 `serde`、`tests` 成了公开模块、
  `MANIFEST.json` 的扁平结构与 Rust 的结构体变体对不上、WIT 包名解析没剥尾部分号。

另有若干条是**测试期望写错而非实现错**，已按文档规则改正：写入后 hash 状态应为
`UnknownHash`（丢了摘要还声称 `MetadataKnown` 才是设计禁止的陈旧声明）；
分页顺序应断言 pre-order 规则而非硬编码名字表；foreign package 的两个接口导出都要改；
「拒绝原因各不相同」该断言的是原因而非 (code, check) 对。

**留待下一阶段**：`tests/integration` 与 `tests/system` 仍在用自己那份手写 fake，
尚未切换到 mock crate 引用。切换后那两份重复可删。

## 5.1 回归工装与四道 Gate

设计基线把 159 条测试用例分成 UT/IT/ST/UAT 四道 Gate，`tests/test_cases.json` 的
`Status` / `Evidence` 两列至今全是 `Not Executed` / 空。该文件**只读**，所以执行证据落在
`mock/` 下，由脚本产出、脚本复跑。

| 文件 | 作用 |
| --- | --- |
| `mock/scripts/run_regression.ps1` | 跑六道 gate，写 `mock/evidence/runs/<ts>/`，再做覆盖自检 |
| `mock/scripts/collect_evidence.py` | 读日志 + `case_map.csv` → 覆盖矩阵 + 汇总 + 报告 |
| `mock/scripts/extract_test_inventory.py` | `cargo test -- --list` → 带 crate 归属的测试清单 |
| `mock/scripts/case_map.csv` | 159 行「设计用例 → Rust 测试」人工策展映射 |
| `mock/evidence/coverage_matrix.csv` | 每条用例的状态、映射测试、实际执行的测试 |
| `mock/docs/REGRESSION.md` | 人读报告 |

`case_map.csv` 是**刻意的人工策展文件**。设计用例说的是「操作者必须观察到 X」，
Rust 测试说的是「代码保证 Y」，仓库里没有任何东西关联二者；从 requirement id 推断
会产出一份看起来完整、实则什么都没断言的矩阵。脚本只负责执行它，不负责猜它。

状态词汇刻意收窄：`PASS` / `FAIL` / `PARTIAL`（映射有笔误或测试被改名）/
`UNMAPPED`（基线有用例但本仓无任何验证）/ `MANUAL`（设计要求人工验收）。

**当前状态**：927 条测试，六道 gate 全绿，覆盖自检 927/927；153/159 条设计用例
已完全映射且执行通过，0 FAIL、0 PARTIAL。剩下 6 条 UNMAPPED 是真实缺口，
已在矩阵里逐条写明原因（取消传播、日志跟随取消、in-use 卷删除保护、UI 延迟、
日志量、UI 认知负荷），其中 UI 类因本仓无 UI 层而不可自动化。

工装本身在这一轮暴露并修掉了三类缺陷，都属于「门禁看起来在工作、其实没有」：

- `CARGO_TARGET_DIR` 只在未设置时才赋值，于是环境里预设的值会让脚本冷构建另一棵树 ——
  门禁验证的构建和开发时验证的不是同一个。
- `Invoke-Gate` 用 `Write-Output` 打进度，PowerShell 会把函数里的一切都返回，
  于是 `$c -ne 0` 拿到的是数组，**五道全绿的 gate 被报成五道失败**。
- 三个 mock crate 自己的测试目标（约 177 条）不归属任何一道 gate，而整套回归都建立在
  这些 fixture 上。补 `mock` gate 后，脚本再拿 `cargo test --workspace -- --list`
  的结果和 gate 实际执行数对拍，**对不上就红**。

最后一条是这套工装的核心判据：**门禁的输入集合必须由发现得出，不能由手写路径得出**。
一条漏配的 gate 和一条全绿的 gate 输出完全一样。覆盖自检就是用来消除这个歧义的。


## 5.2 Windows 打包

`scripts/package.ps1` 一条命令同时产出便携 ZIP 与 per-user MSI，两者由同一份
暂存目录生成，所以**不可能漂移**：

```
dist/SandTree-1.1.0-x64.zip     2.98 MB   解压即用
dist/SandTree-1.1.0-x64.msi     2.41 MB   安装程序，免提权
```

载荷只有 4 个可执行文件 + 许可与说明文档。这不是取巧，是代码实际需要的形态：
`schemas/001_init.sql` 与两个 WIT 都是 `include_str!` 编译进二进制的，
运行期没有任何数据文件要放；kernel 首次运行自建 `%LOCALAPPDATA%\sandtree`。

| 决定 | 理由 |
| --- | --- |
| per-user、不提权 | NFR-S01：管道按用户隔离，daemon 不请求提权 |
| **不修改 PATH** | WiX 的环境变量接口是**覆盖**不是追加。会悄悄改掉用户 PATH 的安装程序，比让用户自己加一个目录糟糕得多；`INSTALL.txt` 给了两条加法 |
| 不注册 Windows 服务 | 服务意味着机器级身份，设计明确不用 |
| 快捷方式单独一个 Feature | 不想要快捷方式的运维可以取消勾选而不放弃二进制 |
| WiX 5 而不是 6/7 | v6+ 要求接受 OSMF EULA。**法律条款不由打包脚本替用户接受**，所以钉在最后一条 MIT 许可线，脚本会在版本不对时直接失败 |

**验证不是「编译 exit 0」**：两个包都被 `msiexec /a` / `Expand-Archive` 真正解开，
逐个核对 `MANIFEST.sha256` 的 SHA-256、核对 4 个 exe 的大小，并实际运行
`sandtree --version`、`sandtree-daemon --version`、`sandtree-daemon --check`
（后者报 31 个方法、0 缺口）。

打包过程本身暴露并修掉了两件事：

- **`--version` 根本不存在**。我写完 `INSTALL.txt` 让用户用它验证安装，解包一跑
  才发现 `sandtree --version` 答 `unknown command`。文档承诺了二进制不兑现的事。
  现已在 CLI 与 daemon 补上（`apps/cli/src/lib.rs::version`），`--help` 里也列出。
- **ZIP 解开是散文件**。`ZipFile::CreateFromDirectory(..., includeBaseDirectory: false)`
  让 9 个文件直接倒在目标目录，没有外层文件夹 —— 解到 Downloads 里就是一片狼藉。
  改成 `true`，与 MSI 的 `%LOCALAPPDATA%\Programs\SandTree` 行为一致。

## 6. license 门禁（cargo-deny 的离线替代）
`cargo deny check` 是 NFR-E03 的门禁，但本机无 `cargo-deny` 二进制且无法联网安装。
`scripts/license_gate.py` 对同一问题做等价审计：

- **license**：读 `Cargo.lock` 拿 name/version/source，再从 cargo registry 取该版本的
  **权威 manifest** 解析 SPDX。数据源顺序是 `registry/src/<n>-<v>/Cargo.toml` →
  `registry/cache/<i>/<n>-<v>.crate`（tarball）。**不能**读 Cargo.lock（没有 license 字段），
  也**不能**读 `registry/index/.cache`（该缓存不含 license 键）。OR 取任一分支可接受、
  AND 需全部可接受、`A/B` 视作 `A OR B`，与 cargo-deny 语义一致。
- **source**：全部 package 必须来自 crates.io，git source 一律拒绝。
- **自失效阈值**：扫不到任何三方包、或解析不出任何 license，直接 FAIL —— 「扫不到」必须与
  「没问题」区分开。
- `scripts/license_gate_mutation_test.py` 做变异验证：确认门禁在输入被破坏时真的会红，
  且还原后按 sha256 校验输入一致。

## 7. 未在本仓实现的部分（及原因）

| 项 | 原因 | 影响 |
| --- | --- | --- |
| `apps/desktop`（Tauri 2 GUI） | 需要完整前端工具链与 WebView2 打包流程，构建体量与验证成本远超本轮；FR-060 的 UI 契约已由 `ipc` 方法族与 CLI 覆盖 | UI 需后续补齐；kernel/CLI 契约不变 |
| `optional/{search-tantivy, git-gix, integration-mcp, agent-observer}` | 设计中明确为 OPTIONAL，且 FR-O01/FR-O02 不属于核心 | 无功能影响 |
| 真实 `.wasm` 组件产物 | 本机无 rustup shim，无法安装 `wasm32-wasip2` target 交叉编译 | `plugin-host` 的 component 加载路径由 WAT fixture 覆盖；ABI 由 `wit/` 与 `schemas/*.wit` 冻结 |
| `Docker Sandboxes` 实验 API 真实联调 | 该 API 为 experimental | provider 以 capability probe + CLI 降级 + fixture 兜底实现（DD-PLG §8 明文要求的三级降级） |
| `cargo deny check advisories` | 无 cargo-deny 二进制 | license/source 两项已由离线门禁覆盖；advisory（RustSec）一项未覆盖 |

## 8. 追溯

`traceability/requirements_to_tests.csv` 记录 FR/NFR → 测试 ID 映射；
新增实现必须补一行映射，并在代码中以 `// FR-xxx` / `// NFR-xx` 标注落点。
