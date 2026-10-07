# SandTree v1.1 — Rust 跨 crate API 契约（冻结）

本文件是实现期的**唯一**跨 crate 接口约定。设计依据：DD-SW §1–§12、DD-PLG、DD-DATA、DD-OBS、DD-SECOPS。
任何人修改本文件中的签名，必须同时更新依赖方并说明理由。

依赖方向（禁止反向）：

```
model ─┬─ observation-model
       ├─ vfs            (纯函数，零 async/IO)
       ├─ policy         (纯函数 + audit/secret redaction)
       ├─ event          (tokio bounded channel)
       ├─ resource-graph (纯内存)
       ├─ store          (rusqlite: repositories + CAS + migration)
       ├─ observation-core
       ├─ sdk            (manifest + provider ports)
       ├─ ipc            (framing + method router + transport)
       └─ kernel         (managers; 通过 port trait 依赖 store/event/vfs)
              ▲
       plugin-host (wasmtime; 实现 sdk ports)
              ▲
       plugins/provider-* , plugins/feature-*  (实现 sdk ports)
              ▲
       apps/{daemon,cli,plugin-worker,probe-windows}
```

硬约束：

1. `crates/{model,observation-model,vfs,policy,resource-graph,kernel}` **不得**依赖
   `rusqlite` / `bollard` / `wasmtime` / `tokio::process` / 任何 provider SDK（NFR-O02）。
2. `vfs`、`policy`、`resource-graph` 不做 IO、不引入 async runtime。
3. 所有跨边界错误用 `sandtree_model::DomainError` + `ErrorCode`（`ST-*`）；provider 原始错误只能进 `detail`。
4. 所有 crate `#![deny(missing_docs)]`、`#![warn(clippy::all)]`；每处实现带 `// FR-xxx` / `// NFR-xx` 追溯注释。
5. 时间统一 RFC3339 字符串（`chrono::Utc::now().to_rfc3339()`）；时长统一 `u64` 毫秒。
6. 所有集合序列化顺序必须确定（`BTreeMap` / 排序 `Vec`），便于 golden test。

---

## crates/vfs — 纯 URI/路径逻辑（无 IO）

```rust
pub struct WorkspacePath { /* 规范化后的相对路径 */ }
impl WorkspacePath {
    pub fn root() -> Self;
    pub fn from_relative(raw: &str) -> Result<Self, UriError>; // 拒绝 .. / 绝对路径 / 空段
    pub fn is_root(&self) -> bool;
    pub fn segments(&self) -> &[String];
    pub fn as_str(&self) -> &str;              // "a/b/c"，无前导斜杠
    pub fn join(&self, child: &str) -> Result<WorkspacePath, UriError>;
    pub fn parent(&self) -> Option<WorkspacePath>;
    pub fn file_name(&self) -> Option<&str>;
}

pub struct WorkspaceUri { resource_id: ResourceId, path: WorkspacePath }
impl WorkspaceUri {
    pub fn root(resource_id: ResourceId) -> Self;
    pub fn parse(raw: &str) -> Result<Self, UriError>;         // stfs://<res>/<path>
    pub fn resource_id(&self) -> &ResourceId;
    pub fn path(&self) -> &WorkspacePath;
    pub fn child(&self, name: &str) -> Result<Self, UriError>;
    pub fn to_uri_string(&self) -> String;
    pub fn redacted(&self) -> String;                           // 诊断用，id 打码
}
impl std::fmt::Display for WorkspaceUri {}

pub enum UriError {
    MissingScheme, UnknownScheme(String), InvalidResourceId(String),
    TraversalDenied { offending: String }, AbsoluteHostPathDenied(String),
    BadPercentEncoding(String), EmptySegment, TooLong(usize),
}
impl UriError { pub fn code(&self) -> ErrorCode; }  // TraversalDenied/AbsoluteHostPathDenied => ST-VFS-001

pub mod confinement {
    /// provider 侧最终确认：把候选路径限制在 root 内。
    pub fn confine(root: &str, relative: &str) -> Result<String, UriError>;
    /// 判断 candidate 是否仍在 root 之下（含符号链接解析后的绝对路径比较）。
    pub fn is_within(root: &str, candidate: &str) -> bool;
    /// host 侧 normalize：把任意 provider path 归一为 stfs 相对路径。
    pub fn to_relative(root: &str, candidate: &str) -> Result<String, UriError>;
}

pub struct MountRecord { pub id: String, pub resource_id: ResourceId,
    pub source_uri: Option<String>, pub target_uri: String, pub mode: MountMode }
pub enum MountMode { ReadOnly, ReadWrite }
pub struct MountRegistry;   // 进程内注册表：insert/remove/get/targets_for/list/resolve
pub struct ReadWindow { pub offset: u64, pub length: u64 }   // read 配额裁剪
pub fn plan_read(offset: u64, length: Option<u64>, file_size: u64,
                 max_single_file: u64, max_total_bytes: u64) -> Result<ReadWindow, UriError>;
```

## crates/policy — capability 决策 + 脱敏 + 信任门禁

```rust
pub struct GrantContext { pub app_id: Option<AppId>, pub plugin_id: PluginId,
    pub resource_id: Option<ResourceId>, pub correlation_id: Correlation }
pub enum Decision { Allow, Deny { reason: String } }
impl Decision { pub fn is_allowed(&self) -> bool; pub fn to_error(&self) -> DomainError; }

pub struct PolicyEngine;
impl PolicyEngine {
    pub fn new() -> Self;
    pub fn grant(&mut self, ctx_app: Option<AppId>, plugin: PluginId, cap: Capability, decision: Decision);
    pub fn revoke(&mut self, plugin: PluginId, cap: &Capability);
    pub fn actual_grant(&self, plugin: PluginId) -> CapabilitySet;      // declared ∩ granted
    pub fn decide(&self, ctx: &GrantContext, requested: &Capability) -> Decision;
    pub fn require(&self, ctx: &GrantContext, requested: &Capability) -> Result<(), DomainError>;
    pub fn dump(&self) -> Vec<(PluginId, Capability, Decision)>;       // 确定性排序
}

pub struct Redactor;
impl Redactor {
    pub fn new() -> Self;
    pub fn redact_value(&self, v: &serde_json::Value) -> serde_json::Value; // 键名匹配
    pub fn redact_text(&self, s: &str) -> String;
    pub fn is_secret_key(key: &str) -> bool;
}
pub const SECRET_KEY_TOKENS: &[&str];   // token,password,secret,apikey,api_key,authorization,credential,private_key,cookie,session

pub struct AuditRecord { pub ts: String, pub actor: String, pub action: String,
    pub resource_id: Option<ResourceId>, pub correlation_id: Correlation,
    pub params: serde_json::Value /* 已脱敏 */, pub result: String, pub error_code: Option<ErrorCode> }

pub struct TrustPolicy { pub min_trust_for_destructive: TrustLevel }
impl TrustPolicy {
    pub fn new() -> Self;                                            // 默认 HostNative
    pub fn check_destructive_precondition(&self, snap: &ObservationSnapshot)
        -> Result<(), DomainError>;                                  // ST-OBS-009 / ST-OBS-003
    pub fn check_staleness(&self, snap: &ObservationSnapshot, now_ms: u64) -> Result<(), DomainError>;
}
```

## crates/event — 类型化事件路由（DD-SW §3 EventRouter）

```rust
pub struct EventFilter { pub event_types: Option<Vec<EventType>>,
    pub resource_ids: Option<Vec<ResourceId>>, pub min_severity: Option<Severity> }
impl EventFilter { pub fn matches(&self, ev: &EventRecord) -> bool; }

pub struct SubscriptionId(u64);
pub struct LagSignal { pub dropped: u64, pub coalesced: u64 }
pub struct Subscription;   // mpsc::Receiver<EventRecord> + filters
impl Subscription { pub fn recv(&mut self) -> Option<EventRecord>;
    pub fn try_recv_lag(&mut self) -> Option<LagSignal>; pub fn close(&mut self); }

pub enum PublishOutcome { Delivered, Coalesced, Dropped(LagSignal) }

pub struct EventRouter { /* subscriber registry + bounded queues */ }
impl EventRouter {
    pub fn new(capacity: usize) -> Self;
    pub fn subscribe(&self, filter: EventFilter) -> (SubscriptionId, Subscription);
    pub fn unsubscribe(&self, id: SubscriptionId);
    pub fn publish(&self, ev: EventRecord) -> PublishOutcome;
    pub fn publish_batch(&self, evs: &[EventRecord]) -> Vec<PublishOutcome>;
    pub fn subscriber_count(&self) -> usize;
}
```

## crates/resource-graph — 内存图（DD-SW §5）

```rust
pub struct ResourceFilter { pub provider_ids: Option<Vec<PluginId>>,
    pub kinds: Option<Vec<ResourceKind>>, pub states: Option<Vec<ResourceState>>,
    pub root: Option<ResourceId> }
pub struct TreeNode { pub resource: ResourceNode, pub children: Vec<TreeNode> }
impl TreeNode { pub fn flatten(&self) -> Vec<&ResourceNode>; pub fn len(&self) -> usize; }

pub struct ResourceGraph;
impl ResourceGraph {
    pub fn new() -> Self;
    pub fn upsert_batch(&mut self, nodes: &[ResourceNode]) -> Vec<Change>;
    pub fn upsert_relations(&mut self, rels: &[Relation]);
    pub fn get(&self, id: &ResourceId) -> Option<&ResourceNode>;
    pub fn children(&self, id: &ResourceId) -> Vec<&ResourceNode>;
    pub fn relations_of(&self, id: &ResourceId) -> Vec<&Relation>;
    pub fn list(&self, filter: &ResourceFilter) -> Vec<ResourceNode>;   // 确定性排序
    pub fn tree(&self, filter: &ResourceFilter) -> Vec<TreeNode>;
    pub fn mark_missing(&mut self, provider: &PluginId, seen: &[ResourceId],
                        grace_ms: u64, now_ms: u64) -> Vec<Change>;    // Unknown→Tombstoned
    pub fn remove(&mut self, id: &ResourceId);
    pub fn len(&self) -> usize;
}
pub enum ChangeKind { Added, Changed, Stale, Removed }
pub struct Change { pub kind: ChangeKind, pub id: ResourceId }
```

## crates/store — SQLite + CAS + migration（DD-DATA §1–§3, §9–§10）

```rust
pub struct StoreConfig { pub path: PathBuf, pub max_read_conns: usize, pub busy_timeout_ms: u64 }
pub struct Store;
impl Store {
    pub fn open(cfg: StoreConfig) -> Result<Self, DomainError>;   // WAL + foreign_keys + user_version
    pub fn open_in_memory() -> Result<Self, DomainError>;
    pub fn migrate(&self) -> Result<(), DomainError>;             // 001_init.sql + user_version
    pub fn integrity_check(&self) -> Result<bool, DomainError>;
    pub fn mark_interrupted_operations(&self) -> Result<usize, DomainError>; // NFR-A03
}

pub trait ResourceRepo { fn upsert_batch(&self, nodes:&[ResourceNode]) -> Result<Vec<Change>,DomainError>;
    fn get(&self,id:&ResourceId)->Result<Option<ResourceNode>,DomainError>;
    fn list(&self,f:&ResourceFilter)->Result<Vec<ResourceNode>,DomainError>;
    fn delete(&self,id:&ResourceId)->Result<(),DomainError>; }
pub trait RelationRepo { fn upsert_batch(&self,rels:&[Relation])->Result<(),DomainError>;
    fn of(&self,id:&ResourceId)->Result<Vec<Relation>,DomainError>; }
pub trait OperationJobRepo { fn insert(&self,req:&OperationRequest,id:&OperationId)->Result<(),DomainError>;
    fn transition(&self,id:&OperationId,state:OperationState,err:Option<ErrorCode>,result:&Json)->Result<(),DomainError>;
    fn get(&self,id:&OperationId)->Result<Option<OperationJobRecord>,DomainError>; }
pub struct OperationJobRecord { /* job row */ }
pub trait EventLogRepo { fn append(&self,ev:&EventRecord)->Result<(),DomainError>;
    fn query(&self,since:Option<&str>,limit:usize)->Result<Vec<EventRecord>,DomainError>;
    fn purge(&self,older_than:&str)->Result<usize,DomainError>; }          // retention 30d
pub trait SnapshotRepo { fn insert(&self,manifest:&SnapshotManifest)->Result<(),DomainError>;
    fn list(&self,resource:&ResourceId)->Result<Vec<SnapshotManifest>,DomainError>;
    fn entries(&self,id:&SnapshotId)->Result<Vec<FileMetadata>,DomainError>; }
pub struct SnapshotManifest { pub id: SnapshotId, pub resource_id: ResourceId, pub created_at: String,
    pub manifest_hash: String, pub entries: Vec<FileMetadata> }
pub trait PluginRepo { /* plugin_package / plugin_instance 读写 */ }
pub trait AppGenerationRepo { /* app_generation 写入 + 原子激活 */ }
pub trait GrantRepo { /* plugin_grant 读写 */ }
pub trait DockerEndpointRepo { /* docker_endpoint 读写 */ }
pub trait WorkspaceMountRepo { /* workspace_mount 读写 */ }

pub struct Cas;   // BLAKE3, objects/<h0h1>/<hash>, tmp/cas-<uuid>.part
impl Cas {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, DomainError>;
    pub fn object_path(&self, hash:&str) -> PathBuf;
    pub fn put(&self, bytes:&[u8]) -> Result<String,DomainError>;   // temp→fsync→rename（已存在则复用）
    pub fn put_stream(&self, r: impl std::io::Read) -> Result<String,DomainError>;
    pub fn get(&self,hash:&str)->Result<Vec<u8>,DomainError>;
    pub fn contains(&self,hash:&str)->Result<bool,DomainError>;
    pub fn gc(&self, referenced:&BTreeSet<String>, grace_ms:u64, now_ms:u64)->Result<usize,DomainError>;
}
```

## crates/sdk — manifest + provider ports（公共 ABI 的 Rust 侧类型）

```rust
pub struct PluginManifest { /* 对应 plugin_manifest_v1.schema.json */ }
impl PluginManifest { pub fn from_json(&Json)->Result<Self,DomainError>;  // ST-PLG-001
    pub fn to_json(&self)->Json; pub fn validate(&self)->Result<(),DomainError>;
    pub fn plugin_id(&self)->&str; pub fn version(&self)->&semver::Version;
    pub fn kind(&self)->PluginKind; pub fn license(&self)->&str;
    pub fn declared_capabilities(&self)->Result<CapabilitySet,DomainError>;
    pub fn supports_hot_swap(&self)->bool; pub fn state_schema_version(&self)->u32; }
pub enum PluginKind { Provider, Feature, Integration, UiContribution }
pub struct AppManifest { /* 对应 app_manifest_v1.schema.json */ }
impl AppManifest { pub fn from_toml(&str)->Result<Self,DomainError>; pub fn to_json(&self)->Json;
    pub fn validate(&self)->Result<(),DomainError>; pub fn required_clusters(&self)->Vec<&str>; }

pub enum ProviderHealth { Healthy, Degraded{reason:String}, Unavailable{reason:String}, Stale }
pub struct DiscoverBatch { pub resources: Vec<ResourceNode>, pub relations: Vec<Relation>,
    pub cursor: Option<String> }

#[async_trait] pub trait ResourceProvider: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    async fn health(&self) -> Result<ProviderHealth, DomainError>;
    async fn discover(&self, cursor: Option<String>) -> Result<DiscoverBatch, DomainError>;
    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError>;
    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError>;
    async fn shutdown(&self);
}
#[async_trait] pub trait ObservationProvider: Send + Sync {
    async fn capabilities(&self, id: &ResourceId) -> Result<ObservationCapabilities, DomainError>;
    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError>;
}
#[async_trait] pub trait FileProvider: Send + Sync {
    async fn list(&self, uri: &WorkspaceUri) -> Result<Vec<FileMetadata>, DomainError>;
    async fn read(&self, uri: &WorkspaceUri, w: ReadWindow) -> Result<Vec<u8>, DomainError>;
    async fn stat(&self, uri: &WorkspaceUri) -> Result<FileMetadata, DomainError>;
    async fn write(&self, uri: &WorkspaceUri, bytes: &[u8]) -> Result<(), DomainError>; // provider 内再做 canonical 检查
}
#[async_trait] pub trait ExecProvider: Send + Sync {
    async fn exec(&self, id: &ResourceId, argv: &[String], timeout_ms: u64)
        -> Result<ExecOutcome, DomainError>;
}
pub struct ProviderDescriptor { pub plugin_id: String, pub version: String, pub kind: PluginKind }
pub struct ExecOutcome { pub exit_code: i32, pub stdout: String, pub stderr: String, pub truncated: bool }
```

## crates/observation-core — 策略协商 / 调度 / 缓存 / 归一化 / 限额（DD-OBS §4, §13）

```rust
pub struct ObservationLimits { pub max_domain_bytes: usize /* 4 MiB */,
    pub max_json_depth: usize, pub max_collection_len: usize, pub max_string_len: usize,
    pub global_concurrency: usize /* 8 */ }
impl Default for ObservationLimits { /* 取 DD-SW §12.3 值 */ }

pub struct StrategyNegotiator { pub allowed_modes: Vec<ObservationMode>, /* provider 可覆盖 */ }
impl StrategyNegotiator {
    pub fn negotiate(&self, caps: &ObservationCapabilities, requested: &[ObservationDomain])
        -> Result<ObservationPlan, DomainError>;                 // ST-OBS-001
    pub fn fallback_plan(&self, caps: &ObservationCapabilities, from: ObservationMode)
        -> Option<ObservationPlan>;
}

pub struct ObservationCache;   // key = resource + domain + profile
impl ObservationCache {
    pub fn new() -> Self;
    pub fn get(&self, id:&ResourceId, domain:ObservationDomain, profile:&str) -> Option<CachedSnapshot>;
    pub fn put(&mut self, id:&ResourceId, domain:ObservationDomain, profile:&str, snap:&ObservationSnapshot);
    pub fn invalidate(&mut self, id:&ResourceId, domain:Option<ObservationDomain>);
    pub fn len(&self) -> usize;
}
pub struct CachedSnapshot { pub snapshot: ObservationSnapshot, pub stored_at_ms: u64, pub age_ms: u64 }
pub fn now_ms() -> u64;

pub struct Scheduler { /* per (resource,domain) coalescing + global limit */ }
impl Scheduler {
    pub fn new(limits: ObservationLimits) -> Self;
    pub async fn observe<F, Fut>(&self, req: ObservationRequest, f: F) -> Result<ObservationSnapshot, DomainError>
        where F: FnOnce(ObservationRequest) -> Fut + Send, Fut: Future<Output=Result<ObservationSnapshot,DomainError>> + Send;
    pub fn in_flight(&self) -> usize;
}

pub mod normalize { pub fn clamp_json(v:&Json, limits:&ObservationLimits)->Result<Json,DomainError>; // ST-OBS-007
    pub fn domain_health(values:&BTreeMap<String,ObservedValue>, requested:&[ObservationDomain]) -> ObservationHealth; }
pub struct ObservationService;  // negotiator + cache + scheduler + provider registry 组合
```

## crates/plugin-host — Wasmtime Component Model + generation 路由

```rust
pub struct Generation(u64);
pub struct RouteTable;      // Arc<RwLock<HashMap<PluginId, Generation>>>
impl RouteTable {
    pub fn current(&self, plugin:&PluginId) -> Option<Generation>;
    pub fn atomic_swap(&self, plugin:&PluginId, g:Generation) -> Generation;  // NFR-P04 ≤250ms
    pub fn rollback(&self, plugin:&PluginId, prev:Generation);
}
pub struct HotSwapOutcome { pub swapped: bool, pub generation: Generation, pub reason: String }
pub struct PluginHost;
impl PluginHost {
    pub fn new(cfg: PluginHostConfig) -> Result<Self, DomainError>;
    pub fn install(&self, pkg: PluginPackage) -> Result<PluginInstanceId, DomainError>;   // verify hash/license/schema
    pub async fn hot_swap(&self, plugin:&PluginId, target:PluginPackage) -> Result<HotSwapOutcome,DomainError>;
    pub async fn rollback(&self, plugin:&PluginId) -> Result<HotSwapOutcome, DomainError>;
    pub fn routes(&self) -> RouteTable;
    pub async fn shutdown(&self);
}
pub struct WasmRuntimeLimits { pub fuel: u64, pub epoch_deadline_ms: u64, pub memory_bytes: usize }
// trap → ST-PLG-002；fuel/epoch 超限 → ST-PLG-002；manifest/hash/license 失败 → ST-PLG-001
// hot swap 失败保留旧 generation（AC-04）
```

## crates/kernel — managers（DD-SW §3）

```rust
pub struct KernelConfig { pub data_dir: PathBuf, pub providers: Vec<PluginId>,
    pub reconcile_interval_ms: u64, pub stale_grace_ms: u64 }
pub struct Kernel;  // owns: PluginSupervisor, ResourceManager, OperationManager,
                    //         WorkspaceManager, SnapshotManager, EventRouter, StoreManager
impl Kernel {
    pub async fn bootstrap(cfg: KernelConfig) -> Result<Self, DomainError>;
    pub async fn discover_all(&self) -> Result<Vec<Change>, DomainError>;      // NFR-A01 单 provider 失败不阻塞
    pub async fn reconcile(&self) -> Result<Vec<Change>, DomainError>;
    pub async fn invoke(&self, req: OperationRequest) -> Result<OperationOutcome, DomainError>;
    pub async fn observe(&self, req: ObservationRequest) -> Result<ObservationSnapshot, DomainError>;
    pub fn tree(&self, f:&ResourceFilter) -> Vec<TreeNode>;
    pub fn inspect(&self, id:&ResourceId) -> Result<ResourceNode, DomainError>;
    pub fn event_router(&self) -> Arc<EventRouter>;
    pub async fn diagnostics_bundle(&self) -> Result<Json, DomainError>;        // FR-066 脱敏
    pub async fn shutdown(&self);
}
```

## crates/ipc — 帧 + 方法 + 传输（DD-DATA §5–§6）

```rust
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;      // 8 MiB
pub struct Request  { pub id: String, pub method: String, pub params: Json, pub correlation_id: Correlation }
pub enum  Response { Ok { id:String, result:Json }, Err { id:String, error:DomainError } }
pub struct EventFrame { pub event: EventRecord }

pub mod framing {
    pub fn encode(payload:&[u8]) -> Result<Vec<u8>, DomainError>;         // u32 LE len + body
    pub fn decode_len(buf:&[u8]) -> Result<u32, DomainError>;           // ST-IPC-001
}
pub trait Transport: Send + Sync {
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError>;
    async fn recv(&mut self) -> Result<Vec<u8>, DomainError>;
    async fn close(&self);
}
pub struct NamedPipeTransport;   // \\.\pipe\sandtree-<sid-hash>-v1；非 Windows 编译为 stub(ST-IPC-001)
pub struct MethodRouter;         // families: resource/operation/docker/workspace/snapshot/plugin/event/diagnostic
impl MethodRouter { pub fn new() -> Self; pub fn register(&mut self, method:&str, h: Handler); }

pub mod method { pub const RESOURCE_LIST: &str = "resource.list"; /* … */ }
```

## apps/probe-windows — 一次性 Probe（DD-OBS §9，`schemas/windows_probe_protocol_v1.md`）

```rust
// 单 binary、固定 capability、无通用 shell（NFR-S07）
// 输出 envelope: <uuid>.part → 原子 rename → <uuid>.json
pub struct Envelope { pub schema: String, pub sandbox_id: String, pub nonce: String,
    pub sequence: u64, pub observed_at: String, pub domains: BTreeMap<String, Json>,
    pub payload_hash: String }
// host 侧校验函数放在 provider-windows-sandbox；probe 侧只负责生成 + 原子写
```

## apps/plugin-worker — 独立 worker 进程（DD-PLG §10）

```rust
// 加载 wasm component，执行 lifecycle/resource-provider，崩溃只影响本 worker
```