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
| ADR-010 | `crates/*` 禁止依赖 mock crate，仅 `tests/*` 可用 | DD-SW §1 | 已实现 |
| ADR-011 | provider-docker 唯一依赖活 daemon 的测试移出默认门禁 | DD-SW §1 | 已实现 |
| ADR-012 | lane 交付由门禁裁决，不由子代理完成声明裁决 | DD-SW §1 | 已实现 |
| ADR-013 | `upsert_docker_endpoint` 把 TCP 端口误判为凭据（缺陷修复） | DD-DATA §4 | 已实现 |
| ADR-014 | discovery 逐页写 relations 触发外键失败（缺陷修复） | DD-SW §4 | 已实现 |

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

---

## ADR-011 唯一一条依赖活 runtime 的测试移出默认门禁

**背景**　`plugins/provider-docker` 的 `health_reports_a_usable_engine_as_healthy`
是全仓唯一一条真正连活的 Docker Engine 的测试（其余用默认命名管道的用例都
不做 IO：构造、`runtime_node`、`resolve_target`；所有降级测试则指向一个
不可能存在的管道）。本轮它红了 —— 不是因为代码坏了，而是本机 daemon 停了，
provider 正确地报了 `unavailable`，而测试要求 `healthy`。

**决策**　标 `#[ignore = "requires a running Docker Engine on the default named pipe"]`，
并在注释里写明在 daemon 可用的机器上用 `cargo test --workspace -- --ignored` 运行。
不删、不弱化。

**理由**　因为一个后台服务停了就变红的门禁不是门禁。但这条测试是真实覆盖 ——
它是「provider 永远降级」与「provider 真的能用」之间唯一的分界，删掉等于放弃
这条断言。标 ignore 同时把「默认门禁可复现」和「有 Docker 时这条覆盖仍然可达」
两件事都保住了。

**规则**　单元测试不得隐式依赖外部 runtime 处于运行状态。确实需要活 runtime 的，
必须显式标记并给出运行命令；同一 crate 内的其余路径应保持与 runtime 无关，
这样「进程没装 Docker」和「Docker 停机」都不影响默认门禁。

---

## ADR-012 并行 lane 的产出由门禁裁决，不由子代理的完成声明裁决

**背景**　三个 mock crate 由三条 git worktree lane 并行产出。子代理通道本轮
10 次派发有 9 次 `net::ERR_CONNECTION_RESET`，磁盘上的 commit 存活而报告丢失。
更关键的是：三个 lane 交付时**全部是红的**，其中 `mock/runtime` 的
`discover_all` 存在无法终止的无限循环（堆到分配器失败 288MB），
`mock/wasm-components` 则从未编译过。

**决策**　每条 lane 在 merge 前必须由主线亲自跑完整门禁（fmt / clippy / all-targets /
test / license），并逐条核对失败项是「实现错」还是「测试期望错」，后者按文档规则改正。
lane 内保留 checkpoint commit，避免通道断线时丢失工作。

**后果**　隐藏缺陷的分布印证了这个判断：`tests/world.rs` 的 5 条失败从未在任何一次
早期门禁里出现过 —— 套件在它之前就中止了。「跑过」与「跑全过」是两件事。

**规则**　报告「某部分已验证」时，写的是**实际跑过的门禁**，不是仓库拥有的门禁。
未执行到的测试目标必须显式说明。

---

## ADR-013 `upsert_docker_endpoint` 把 TCP 端口误判为凭据（缺陷修复）

**问题**　`crates/store` 的 NFR-S03 校验把「authority 中第一个 `@` 之前含有 `:`」
当成嵌入凭据。这个启发式无法区分 `user:password@host` 与 `host:2376` —— 二者都满足
「含 `:` 且不以 `//` 开头」。结果是**任何 TCP 形式的 Docker 端点都被拒绝存储**，
返回 `ST-POL-001 docker endpoint URI must not embed credentials`。命名管道与
unix socket 不受影响（其 authority 为空），所以只测这两条路径的用例全绿。

**影响**　UAT-018「非 Desktop Docker 端点可寻址」所覆盖的远程 engine 场景完全不可配置：
非本机 Docker、TCP 远程 daemon、SSH 隧道暴露的 TCP 端口都存不进 store。这是 NFR-E02
的直接反例，也使该用例的「可寻址」半边无法成立。

**决策**　按 RFC 3986 判定：URI authority 为 `<userinfo@>host[:port]`，因此
**authority 中出现 `@` 即为携带身份**。端口分隔符 `:` 不再参与判定。

- `tcp://10.0.0.5:2375`、`tcp://docker.internal:2376` —— 接受
- `tcp://admin:hunter2@10.0.0.1:2375`、`tcp://admin@10.0.0.1:2375` —— 拒绝（用户名本身也是 userinfo）
- `npipe:////./pipe/docker_engine`、`unix:///var/run/docker.sock` —— 接受

**连带**　诊断 bundle 的 `strip_userinfo` 成为纵深防御而非唯一防线：store 已在源头拒绝，
bundle 仍对历史遗留行脱敏（UAT-015 同时验证两层）。

**回归门禁**　`crates/store/src/repo.rs::a_tcp_port_is_not_mistaken_for_a_credential`，
一条用例同时钉住「合法 TCP 必须可存」与「凭据必须被拒」两侧，并断言拒绝信息引用 NFR-S03。

---

## ADR-014 discovery 逐页写 relations 触发外键失败（缺陷修复）

**问题**　`resource_relation` 声明 `FOREIGN KEY(from_id/to_id) REFERENCES resource(id)`。
`ResourceManager::discover_all` 的写法是每取回一页就立刻
`upsert_resources(&batch.resources)` 再 `upsert_relations(&batch.relations)`。但分页遵循
provider 的 pre-order，**第 0 页的一条关系完全可以指向第 1 页才投递的资源**。
此时整次扫描以 `FOREIGN KEY constraint failed` 失败。

**为什么一直没被发现**　只有「关系跨越分页边界」的 provider 会触发。无关系的 fixture、
或关系两端同页的 fixture 全部通过。`DOCKER_WORLD` 是仓库里第一个 page_size=3、
关系跨页的 fixture —— 它此前从未被送进 kernel 的 discovery 路径（本轮 UAT 才第一次）。

**决策**　关系在**扫描结束、游标链走完之后**统一写入一次（FR-061：关系只有在其
两端资源都存在时才有意义）。资源仍逐页写入以保持 `last_seen` 的新鲜度语义。

**失败与降级的区别**　扫描中途 provider 报错时 `break`，此时缓冲的关系不再写入，
该 provider 本轮的关系集合保持上一次成功扫描的状态 —— 不会写入指向未知资源的边。

**回归门禁**　`tests/integration/tests/discovery.rs::relations_that_span_a_page_boundary_are_still_written`，
用例先断言 fixture 确实分页且确实存在跨页关系（否则测试会证明不了任何东西），
再断言两端资源与关系本身都在库里、且资源数精确为 5。

---

## ADR-015 网络取回通道（git remote / MCP endpoint）——新增 optional provider plugin

**背景与方向**。沙盒内部有一类内容无法安全穿透取得：runtime 没有 read API，
没有 exec 通道，而要打通另一条路就要交出宿主 Docker socket、全盘可写映射或宿主管理员 token——
NFR-S06/S07 明确禁止。对这部分内容，沙盒可以选择**主动发布**一个通道（git remote / MCP endpoint），
让宿主去网络取。本 ADR 把这种能力落到两个新增 optional provider plugin 上，并先定下它们不能造成的安全回退。

**为什么不能复用基线的 FR-O02**。基线 `FR-O02`（01_需求定义:328-332）的 MCP Adapter 是**向外**方向：
把 SandTree 的操作暴露**给**兼容 Agent，且明写“MCP 不属于 Kernel 内部协议或必需依赖”。
本次需求是**向内**方向：沙盒主动挂出端点，SandTree 去取。两者不共用代码也不共用协议面，
语义相反，不能复用。基线 `03_系统架构设计:62,115` 已给 `optional/{git-gix, integration-mcp}` 留位，
本 ADR 就落在那两个位置上，但中的 git 定位是“optional workspace metadata”，与此处的“经网络取沙盒内资产”不是一件事。

**决定 1：落点是新增 optional provider plugin，不动冻结 schema**。两个 crate：
`plugins/provider-git-remote`、`plugins/provider-mcp-remote`。它们走既有的 `ObservationProvider` 端口产出标准
`ObservationSnapshot`，因此 `schemas/001_init.sql`、`observation_snapshot_v1.schema.json`、全部 WIT 一字未动。

**决定 2：准入规则落在 `crates/policy/src/acquire.rs`，且无传输依赖**。规则是纯函数，
可以不开网络就测，并且两个 provider 被迫走同一道门。规则只有一条，但是两个方向：

- **穿透被拒绝时**，网络取回才成立。
- **穿透可行时**，网络取回必须被拒绝。

第二个方向才是重点。只写前一半的话，沙盒就能自己挑选更弱的观测方式：
把宿主的自己的 read API 藏在连可达范围外，让穿透看起来不可用，然后让每一个关于自己的事实
由一个自己控制的进程送达。**网络通道是不可达内容的兜底，不是一个更方便的选择**。

**决定 3：信任上限锁 `GuestProbe`，且是类型属性而不是配置项**。
`AcquisitionPolicy` 是**无字段**单元结构，`NETWORK_TRUST_CEILING` 是 `const`，`AcquisitionPermit` 的字段私有且只能由
`AcquisitionPolicy::authorize` 产出。因此“把信任提高”不是一个需要记得住的约定，而是没有任何代码路径可以达到的状态。

**决定 4：git 提供 integrity，不提供 authenticity**。对象 ID 是内容寻址的，所以同一份字节以后可以重新核对。
这就是 `Provenance::evidence_hash` 的用途。但沙盒可以为自己的假陈述算出一个合法对象 ID，
所以信任档位不动——严格遵循 ADR-OBS-003。`evidence_hash` 绑定**全部** ref/工具清单，
而不只是 HEAD；只哈 HEAD 的实现会在沙盒改写其他分支时仍然“校验通过”。

**决定 5：不用 gix/gitoxide，自实 git ref advertisement**。基线把 `gix/gitoxide` 列为 OPTIONAL git 技术，但：

- 本机离线仓储里 `gix` 所有版本都解析失败（`prodash -> human_format` 缺包），强行引入会打断整个 `--offline` 门禁；
- 本通道需要的原语只有一个：`info/refs` 的 pkt-line ref advertisement，约百行，而且**不需要 git 可执行斄体就能测**；
- `git2` 需要在构建时编译 libgit2（C + cmake），用以读一份 ref 清单不等价。

实测结果记录在本 ADR 的「强行不可行的方案」一节。

**决定 6：MCP provider 只调 `initialize` + `tools/list`，绝不调 `tools/call`**。
调一个工具是执行沙盒选定的代码、带沙盒选定的参数，把返回值当成观测结果。
这使被观测者反过来操作观测者，并且这条路径的副作用是 observation 平面无法推理的——
它正好是 NFR-S06 把 guest probe bootstrap 限定为只读所防住的那种形状。

### 强行不可行的方案（实测记录）

- `gix 0.66 / 0.73 / 0.84`：三个版本在本机离线解析均失败，均为
  `no matching package named human_format` （`prodash 28/30` 的依赖，本机缓存无此包）。
- `git2 0.21` + `libgit2-sys`：需构建 libgit2 C 代码，且依赖 cmake / cc 链。
- `reqwest`：需拉 TLS 栈且与 hyper 重复；最终采用 `hyper` + `hyper-rustls`，原因是 `Cargo.lock` 已有 hyper。
- **TLS 确认可行**：`hyper-rustls 0.27` + `rustls-native-certs`（系统信任库）+ `ring`（不用 `aws-lc-rs`，后者需 cmake），
  全部在本机离线缓存内并成功编译。证书验证**6号一起**：没有关闭验证的后门。
- `ring` 许可为 `Apache-2.0 AND ISC`，两项均在 `schemas/deny.toml` 白名单内，`scripts/license_gate.py` 实测 PASS。

### 交叉验证：端到端，真实 socket

两个 provider 各自带一个 `tests/e2e.rs`，起真实 loopback HTTP 服务器，走生产代码的
`HyperTransport` -> pkt-line/JSON-RPC 解析 -> 快照装配全路径。唯一替换的是 TLS 连接器的**目标地址**。

git 端的服务器返回的是按 git-http-backend 真实形状组装的 pkt-line 报文；
MCP 端的服务器是一个真实的 MCP 实现——按 `id` 关联、赋予 session、按 `Accept` 协商返回 JSON。

**这些测试真的抓到了东西**：

1. **MCP session 从未回显**。手工单元测试全绿，但端到端断言 `tools/list` 必须携带手握手时
   分配的 `Mcp-Session-Id`。原因：`call()` 只返回解析后的 JSON-RPC `Response`，把 HTTP 响应头里的
   session 丢了，`probe()` 里硬编码为 `None`。它在一个宽容 session 的服务器上看不出任何问题，
   只是在严格的服务器上才显形。
2. **URL path 里的空格未被拒**。`https://host/repo.git --upload-pack=touch /tmp/pwn` 能过入之前的校验。
   `git clone` 会把 path 之后的一切当选项，这就是戴着 URL 皮的远程命令执行。现在在解析阶段就拒，
   并拥有一条专门的反证测试。

**门禁没有发现的事**（写清以免误认为已覆盖）：端到端测试只覆盖 loopback 上的
`http://`；`https://` 路径有 TLS 可链但**没有对真实证书算法做过验证**。

### 已知缺口（明确写出，不装作已完成）

- **git 协议 v2 不支持**。客户端不发 `Git-Protocol: version=2`，符合规范的服务器因此回 v0 advertisement；
  若服务器仍回 v2，报 `ProtocolVersion2Unsupported`，而**不是**报“0 个 ref”。
- **不拉 packfile，不读文件内容**。只有 advertisement。通道能学到工作区的形状，拿不到文件内容。
- **不调 MCP 工具**。见上。
- **网络取回尚未接入 kernel 的协调子（strategy selection）**。两个 provider 已完整实现 `ObservationProvider`，
  但 `crates/observation-core` 尚未在拒绝穿透时回退到它们。这是本次交付的**最大缺口**：
  在接上之前，这两个 plugin 只能被直接注入并调用。
- **`PenetrationVerdict` 由调用方注册**。provider 自身不会去推导穿透可能性，禁用时默认拒绝。
- **没有 UI 层**，命令行也没有接入端点注册。

**反证测试**：`crates/policy/src/acquire.rs` 的 48 条测试 + 三次真实变异验证。
变异【穿透可行不再拒绝】-> `a_working_penetration_channel_makes_the_network_channel_inadmissible` 变红；
变异【信任上限提到 provider_native】-> 两条 ceiling 测试变红；
变异【删掉 verdict 的域绑定】-> `a_verdict_judged_for_another_domain_is_not_accepted` 变红。

**当前测试规模**：`acquire` 48 条 + git-remote 72 条（63 单测 + 9 端到端）+ mcp-remote 55 条（48 单测 + 7 端到端）= 175 条新增。
