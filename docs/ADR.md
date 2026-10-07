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