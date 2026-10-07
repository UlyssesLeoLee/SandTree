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

---

## ADR-016 generation 权威归属：RouteTable 单一权威 + LoadedGeneration 配对（架构统一）

**背景**。热插拔在实现上是完整的：`crates/plugin-host/src/hot_swap.rs` 把 DD-PLG §4 图 4-1
逐条实现并被单测钉住顺序。但整条路径**在产品上不可达**——`plugin.hotswap` / `plugin.install` /
`plugin.rollback` 五个方法全在 `apps/daemon/src/methods.rs` 的 `not_served` 名单里，而
`apps/daemon/Cargo.toml` **根本没有依赖 `sandtree-plugin-host`**。`PluginHost` 这个注册表全仓零
非测试调用方。App Cluster 更彻底：`AppManifest.clusters` 能解析能校验，但没有任何代码读它去装配。

在补端点之前，先审了一遍「两条 provider 链怎么统一」，发现的问题比端点缺失更根本：

| 概念 | 位置 | 谁读它 |
| --- | --- | --- |
| `RouteTable: PluginId -> Generation` | `plugin-host/route.rs` | 只有 supervisor 和测试 |
| `PluginHost: PluginId -> Arc<dyn GenerationRuntime>` | `plugin-host/lib.rs` | **没有人** |
| `ProviderInstance { plugin_id, generation, ports }` | `sdk/ports.rs` | kernel 全部路由 |

一个 generation 被**两个类型描述、两个 map 存放，而且没有任何东西检查它们一致**。

**决定 1：`RouteTable` 存实例，不只存数字**。这是本次最实质的修复。
原设计里「原子 swap」= 一次 `map.insert(generation)`，但那只是一半：路由指针动了，实例注册表
没动，于是存在一个窗口——**路由指向 gen2，但 host 拿不出 gen2 的对象**。这正是 DD-PLG §4 的
原子性要防的事，而它恰恰发生在「swap 本身」这一步。两个 map 的两次写，再怎么小心也关不掉这个窗口，
因为它们不在同一个临界区。

改为 `RouteTable: PluginId -> Arc<LoadedGeneration>`，swap 变成一次写，同时完成「换指针」和
「交出对象」。`current()` 直接返回被路由的那个 `Arc`，调用方不再需要第二次查找——也就没有第二次
查找可能看到另一个 generation 的可能。

**决定 2：`LoadedGeneration` 把生命周期和端口绑成一个值**。
`GenerationRuntime`（init/health/prepare/accept/drain/shutdown）与 `ProviderInstance`
（resource/observation/files/exec）是两件事，但**同一个 generation 的两个视图**。构造时
`plugin_id` 与 `generation` 由 host 覆写（`LoadedGeneration::new`），所以调用方无法把一个自称
gen999 的端口包塞进来当 gen7 用。kernel 的 `ProviderRegistry` 随之降级为**投影**
（`ports_for_registry()`），由 route table 产生，不是权威。

**决定 3：`StateMigration` 是具名枚举且不携带 schema 版本**。
原来是 `swap(..., stateful: bool, ...)`——调用点上的 `true` 不说明走的是哪条分支。改成
`None` / `Required` 两态。更重要的是：**版本号一律从两侧 generation 的 descriptor 读**。
中途我一度让 `Required` 带上 `state_schema_version` 让调用方传，那是倒退——调用方可以谎报
入版本从而绕过 NFR-M02 的降级拒绝，已撤回，并由
`the_schema_verdict_comes_from_the_generations_not_the_caller` 钉住。

**决定 4：App Cluster 用一次批量发布**。
逐个 `atomic_swap` 不是原子的：一个 app 通常是控制面 + 它控制的东西，发布到一半会留下「新控制面
在线、旧数据面还在」的窗口——**半升级的 app 比没升级的 app 更糟，因为它看起来成功了**。
路由表是单锁 `BTreeMap`，所以 `atomic_publish` 拿一次写锁写 N 条，整 app 同时生效。
`required: false` 的集群按 manifest 语义丢弃并在 `skipped` 里报告原因，而不是静默。

**决定 5：删掉 `PluginHost`**。它是 `RouteTable` 的重复实现，且零调用方。留着它等于给未来留一个
「可以往这里塞东西」的第二权威。

**决定 6：`discard!` 宏拆成 `StagedFailure`**。
原宏把「关掉 staged 实例 + 返回拒绝」藏在 5 个调用点，任何新增的可失败步骤都可能新增一条泄漏路径
而不自知。现在所有 swap 前失败汇到一处（`StagedFailure::discard`），新增步骤不可能绕过它。
`discard-staged` 审计步保留在 trace 里。

**顺带修正的两处测试陷阱**（都是重构过程中被新断言照出来的）：
- `accept-upgrade` 调的是**入站** generation。测试原先在旧代上断言这条调用，读旧代会**空洞通过**。
- 进程级 `static` shutdown 计数器在并行测试下互相污染。改为每个 generation 独立计数。

**回归门禁**　`crates/plugin-host/src/{generation,route,hot_swap,cluster}.rs` 共 62 条，
其中直接钉住本 ADR 的是：`the_ports_generation_is_rewritten_to_the_hosts_authority`、
`the_routed_generation_and_its_instance_are_always_the_same_value`、
`the_supervisor_hands_back_the_retired_generation_for_rollback`、
`the_schema_verdict_comes_from_the_generations_not_the_caller`、
`a_failed_required_slot_publishes_nothing`、
`migration_reaches_the_generation_the_old_one_was_asked_to_target`。

**已知缺口（未在本 ADR 范围内解决）**。
1. `plugin.install` / `plugin.hotswap` / `plugin.rollback` 端点仍未接线——daemon 尚不依赖
   `sandtree-plugin-host`。本 ADR 只统一了机制，未把它接到产品。
2. `ComponentGeneration` 仍未实现 `ResourceProvider`：WIT 的 `provider-plugin` world 导出了
   `resource-provider`，但 adapter 未实现，所以 WASM 组件目前只能 lifecycle-only 上线。
   `LoadedGeneration::lifecycle_only` 正是为这个中间态准备的。
3. in-process Rust provider 与 WASM 组件的**生成号分配**仍未统一：前者由调用方指定，后者由
   `ClusterPlanner::first_generation()` 给出。
### ADR-016 补记：自审在接线后又查出两个 generation 泄漏

ADR-016 落地后对同一块代码做了一轮自审，查出两个**资源泄漏**——都属「代被挤出路由表后没人退役」这一类，
在 WASM generation 上的后果是 guest 的 `lifecycle.shutdown` 永不执行。

**缺陷 1：对已安装插件重复 `plugin.install` 会泄漏旧代。**
`supervisor.install` 其实把被挤出的代放在了 `SwapResult::retired` 里，但 `PluginControl::install`
直接丢弃了整个 `SwapResult`。变异验证确认：去掉守卫前，第二次 install 会**成功**
（`swapped: true, generation: gen2`，`drained: false`），留下一个既没 drain 也没 shutdown 的
gen1，且回滚把手一并丢失。
**修法不是补 drain，而是让误用在源头不可达**：`install` 在插件已有 serving 代时直接拒绝，
并指名 `plugin.hotswap`。这样 install 与 hotswap 互为对称守卫——各自在错误状态下拒绝并指向对方。

**缺陷 2：并发 swap 时被挤出的那一代会泄漏。**
`publish` 里有两个代：`previous`（supervisor 迁移来源，回滚目标）与 `rolled`（路由表实际挤出的）。
正常情况下二者同一个；但**同一插件的两个并发 swap** 会让它们不同——调用方读到路由后、原子写之前，
另一条 swap 抢先落地。原代码 drain 了 `previous` 后把 `retired` 覆盖成它，`rolled` 就此失联：
既没人路由，也没人退役。
**修法**：凡是不作为回滚目标交还的挤出代，一律 drain + shutdown，并打 warn 日志说明是并发所致。
判据是「谁被交还」而不是「谁先被读到」。

**门禁**　`installing_over_a_live_plugin_is_refused_and_names_the_right_method`、
`a_generation_displaced_by_a_racing_swap_is_still_retired`，两条均经变异验证（去掉修法立刻变红）。

---

## ADR-017 WASM 插件路径的端到端验证：先证明它可达，再谈它正确

**背景**。`3e8203e` 把 `ComponentGeneration` 接上了 WIT `resource-provider`，但那一步的全部验证
都止于 `decode` 契约：把 guest 返回的字符串喂给 `serde_json`。**`discover` / `inspect` /
`invoke` 三个方法本身从未被驱动过。** 这不是「覆盖不足」，是「无法运行」——因为没有任何组件能通过
`instance not valid to be used as export`，fixture 编译不过。

本 ADR 记录为了让它跑起来而做的三件事，其中第三件是本仓最重要的发现。

### 1. canonical ABI 的三条规则（实测，不是推断）

逐签名二分（每个签名单独编译一个最小 component，看 encoder 的判决）定下三条：

| 规则 | 内容 | 违反时的报错 |
|---|---|---|
| **实例必须导出自己签名用到的类型** | `(instance $lifecycle (export "descriptor-record" (type $dr)) ...)` 是让实例可作为 export 的那**一行** | `instance not valid to be used as export` |
| **返回区指针是 core 函数的 `i32` 返回值，不是额外参数** | `canon lift` 由 guest 分配并返回地址；`canon lower` 才由 host 传入 | `lowered parameter types [...] do not match parameter types [...]` |
| **unit ok-payload 不让 `result` 变便宜** | `result<_, string>` 是 `[disc, err_ptr, err_len]` 三个 i32，仍然超过 `MAX_FLAT_RESULTS` | 同上 |

第二条最容易记反，记反的代价是每个函数各改一轮。ADR 与 `mock/wasm-components/src/engine.rs`
都记了「先前那份错误病因是什么、被哪次否证推翻」，因为**错误的病因比没有病因更糟**——它会把下一个
人带进一条死路（此前记录的「命名类型身份别名」就是这样，它推出的补救 `(alias outer ...)` 在
component 类型位置上根本不解析，`outer` 是 core alias kind）。

### 2. fixture 语料由生成器产出

五个 fixture 现在由 `mock/scripts/gen_fixtures.ps1` 从同一份模板生成，派生件之间**只有导出块不同**。
这让 `fixtures.rs` 里「派生件就是有效件改了一处」这句话从「靠人记得同步的 diff 断言」变成结构性事实。

fixture 内嵌的 JSON 由 `tests/provider_binding.rs::the_valid_fixture_matches_the_dtos_it_embeds`
对照产品 DTO 的 serde 输出来校验：DTO 一改，fixture 立刻红，并指向重新生成的命令。

### 3. 缺陷：feature-gated 的代码不在门禁里（ADR-017 的真正内容）

让端到端测试跑起来之后，第一次编译 `wasmtime-abi` 就暴露了三件事，全都不是新代码的错，而是
**从来没被编译过**：

1. **`ComponentGeneration::load` 在 arm 之前就调 guest。**
   `epoch_interruption(true)` 下，store 的 epoch deadline 初值是 0，而引擎 epoch 已经过去了：
   未 arm 的调用在 guest 执行第一条指令之前就 `wasm trap: interrupt`。
   `load` 读 `lifecycle.descriptor` 是唯一一个走不到 `self.arm` 的调用点（那时 `self` 还不存在），
   于是**任何组件都装不上**。修法是把 arming 拆成 `arm_with(limits, store)`，让 `load` 在构造
   `Self` 之前就用同一份预算 arm 一次——一份实现，一个不变量。

2. **`Worker::load` 编译不过**（`Arc<LoadedGeneration>` 缺 `clone`、`LoadedGeneration` 未包 `Arc`、
   `Arc<ComponentGeneration>` 未向 `Arc<dyn ResourceProvider>` 转型）。整个插件加载通道在
   `wasmtime-abi` 下从未构建成功。

3. **`ComponentGeneration::serialize()` 产出的是原生目标文件**（本机以 `\x7fELF` 开头），不是 component
   二进制；把它喂回 `Component::new` 会报 `input bytes aren't valid utf-8`，读起来像文本解析问题、
   其实不是。取字节必须用 `wat::parse_str`。

**根因是一条结构性的**：`cargo test --workspace` 与 `cargo clippy --workspace` 都不启用任何
non-default feature，因此所有 `#[cfg(feature = ...)]` 的模块**不在门禁里**；而回归脚本的覆盖自检
用 `cargo test --list` 统计「workspace 拥有多少测试」——**该命令只列出已编译的测试**，所以这个
量具的输入集已经把 feature-gated 的那部分排除在外了。量具漏扫与扫描结果干净，在外观上完全一样。

**结构性修法**（三条，缺一不可）：
- `AGENTS.md` 的门禁改为 `cargo clippy --workspace --all-targets --all-features` /
  `cargo test --workspace --all-features`；
- `mock/scripts/run_regression.ps1` 新增 `mock-engine` gate 显式编译 engine 语料，并**断言它至少
  跑了 1 条**——编译了零个的 gate 比没有 gate 更糟，它会安静地贡献 0；
- 覆盖自检额外用 `--features sandtree-mock-wasm-components/engine --list` 列一次，把差值计入
  `owned`，让「漏跑的 feature-gated 测试」重新变成可被抓到的缺口。

**门禁**　`tests/provider_binding.rs` 9 条：descriptor / 七个 lifecycle 调用 / discover / inspect /
invoke 全部走真实 guest；外加一条「装不上的组件在服务任何东西之前就被拒」。
`mock-engine` 语料 7 条。变异验证：`load` 里去掉 `arm_with` 立刻变红（component 装不上）。

---

## ADR-018 插件装载路径：先让它真的能装，再谈进程隔离

**背景**。ADR-016 把四个插件端点从 `not_served` 里搬出来并接上 `HotSwapSupervisor`，
但 `PluginControl` 的 `PluginLoader` 只有一个 `UnavailableLoader`——端点是「已注册」的，
**每一个都恒定拒绝**。这两种不可达长得一模一样，而这正是本仓反复清掉的那种形状。

ADR-017 之后组件能编译能绑定了，于是「组件能跑」与「产品能装」之间剩下的就只是装载路径。
本 ADR 记录把这段补上的做法，以及一处**刻意的设计偏离**。

### 1. `PluginLoader::stage` 缺一件东西：字节从哪来

`stage(plugin, generation)` 只收到插件 id 和代数——这是对的，控制平面本就不该知道字节在哪。
所以包来源是另一个可注入的关切（`PackageSource`），不是一个参数。

`DirectoryPackages` 的索引方式本身是有讲究的：目录名**不是**身份。插件身份是
`PluginId::derive(&[<manifest plugin_id>])`，即一串 `plg-<hex>`——当 map key 好用，
当运维要敲的目录名毫无用处。所以索引是「遍历 `plugin.json` 并推导 id」，
装一个插件就是丢个目录进去，而不是先算个哈希再 mkdir。

顺带得到两条免费的不变量：两个包声明同一身份是**部署期**错误（否则「我装的是哪个」
变成掷硬币）；磁盘上任何一份解析不了的 manifest 在**启动时**就炸，而不是等某个运维
恰好去装它的时候。

### 2. 偏离：worker 跑在 daemon 进程内（FR-055）

DD-PLG §10 与 FR-055 要求 worker 是**独立进程**， blast radius 落在它自己身上。
本轮实现的 `WorkerLoader` 没有做到这一点，它在 daemon 进程内 stage。

**保住了什么**：guest 的内存安全与能力限制与它的 store 在哪儿无关。一个 trap 就是 trap，
WASM guest 无法损坏宿主内存。

**丢掉了什么**：宿主侧 worker 代码本身的隔离，以及独立进程才有的 OS 级资源上限。

因此它**不是 daemon 的默认 loader**。`PluginControl::unavailable` 仍然是出厂默认，
没显式选择这个 feature 的构建仍然拒绝而不是假装。开启它是一个决定，不是副作用——
feature 名 `in-process-worker`，默认关闭，且注释里写明它为什么默认关闭。

### 3. 门禁：三条真实端到端

`mock/wasm-components/tests/` 下三组，全部无 stub：

- `worker_loading.rs`（7 条）——`Worker::load` 跑真实组件：descriptor、resource port、
  生命周期 runtime 与 generation 号三者的**同一性**、init 后服务、retire 会 drain+shutdown、
  许可证被拒时连引擎都到不了。
- `daemon_install.rs`（6 条）——从磁盘上的包到路由：`install` 发布并把 provider 流量送到组件、
  重复 install 被拒并指名 `hotswap`、`hotswap`+`rollback`、disable 清理回滚储备、
  许可证被拒不产生任何路由、插件不在磁盘上时路由为空。
- `provider_binding.rs`（9 条，ADR-017）。

其中一条断言强度值得单说：`rollback_returns_to_the_first_generation` 用
`Arc::ptr_eq` 断言**回滚恢复的是当初被挤出的那一个 generation 实例**，
而不是重新 stage 一个看起来等价的。这条断言挡住的正是 ADR-016 之前那类「路由指向了
另一个实例」的问题，而它在纯文本断言下会一直绿。

### 4. 剩下的（不是阻塞，是没做）

- **进程隔离**（FR-055）。真正的做法是 daemon spawn `sandtree-plugin-worker`
  子进程、用 `crates/ipc` 的 `Transport` 代理 `GenerationRuntime` 与 `ResourceProvider`。
  `apps/plugin-worker/src/main.rs` 目前仍是空的 `fn main() {}`，`crates/ipc` 也没有
  客户端 transport。这三件是下一个 ADR 的内容，形状已经由 `PluginLoader` 这个接缝定死了。
- **`diagnostic.version` 之外的可观测**：daemon 现在能装了，但没有任何界面把
  「插件已安装 / 正在服务第几代」显示出来。