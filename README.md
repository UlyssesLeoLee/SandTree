SandTree

A unified control plane for AI sandboxes, workspaces, agents, and development environments.

SandTree 是一个使用 Rust + Tauri 构建的本地 AI 开发环境管理平台。

它将 Windows Sandbox、Docker Sandbox、Multipass、Docker、Kubernetes、Git Worktree、AI Coding Agent 以及其中的文件系统统一抽象为一棵可观察、可操作、可检索的树。

目标不是再做一个虚拟机管理器。

SandTree 希望解决的是：

AI 时代，本地开发环境正在变成大量 Sandbox、Worktree、Agent、容器与任务组成的分布式工作空间，而开发者缺少一个统一的控制平面。

⸻

Concept

传统开发环境通常是：

Developer
   ↓
IDE
   ↓
Repository

AI-native 开发正在变成：

Project
   ↓
Task
   ↓
Worktree
   ↓
Sandbox
   ↓
Agent
   ↓
Containers / Services
   ↓
Files / Logs / Tests

当多个 Agent 并行工作时，开发者需要知道：

* 哪个 Task 对应哪个 Worktree
* 哪个 Agent 正在哪个 Sandbox 中运行
* Sandbox 内有哪些文件发生了变化
* 哪些服务正在运行
* 哪个环境占用了多少资源
* Agent 修改了什么
* 某次任务执行前后的状态差异
* 如何在 Windows、Linux、Container、Kubernetes 之间统一操作

SandTree 为这些资源建立统一模型。

⸻

🌳 Tree-first

SandTree 的核心不是 VM，也不是 Container。

核心是：

Project
│
├── Task
│   │
│   ├── Worktree
│   │
│   ├── Execution Environment
│   │   │
│   │   ├── Sandbox
│   │   ├── VM
│   │   └── Container
│   │
│   ├── Agent
│   │
│   └── Files
│
└── Integration Environment

例如：

STAR
│
├── STAR-101 Auth Refactor
│   │
│   ├── wt/star-101
│   │
│   ├── Docker Sandbox
│   │   ├── Codex
│   │   ├── PostgreSQL
│   │   └── Redis
│   │
│   └── Workspace
│       └── src/
│
├── STAR-102 Windows Updater
│   │
│   ├── wt/star-102
│   ├── Windows Sandbox
│   └── Windows Agent
│
└── Integration
    │
    └── Multipass
        └── k3d
            ├── auth-service
            ├── redis
            └── postgres

SandTree 将这棵树作为开发环境的真实拓扑。

⸻

Why SandTree?

现有工具通常只管理自己所在的层：

Hyper-V Manager
→ VM
Docker Desktop
→ Container
Docker Sandboxes
→ Sandbox
Multipass
→ Ubuntu VM
k9s / Lens
→ Kubernetes
Git
→ Branch / Worktree

但 AI 开发真正关心的是它们之间的关系：

Task
 ↓
Worktree
 ↓
Sandbox
 ↓
Agent
 ↓
Service
 ↓
File

SandTree 在这些基础设施之上增加一个统一的：

Execution Fabric + Workspace Fabric + Intelligence Fabric

⸻

Architecture

┌─────────────────────────────────┐
│          SandTree Desktop       │
│             Tauri               │
│                                 │
│ Tree / Files / Tasks / Diff     │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│         SandTree Daemon         │
│                                 │
│ Resource / Task / Workspace     │
│ Snapshot / Search / Events      │
└────────┬───────────┬────────────┘
         │           │
         ▼           ▼
┌──────────────┐  ┌────────────────┐
│  Providers   │  │ Workspace Core │
├──────────────┤  ├────────────────┤
│ Local FS     │  │ VFS            │
│ Git          │  │ Index          │
│ Docker SBX   │  │ Snapshot       │
│ Windows SBX  │  │ Diff           │
│ Multipass    │  │ Search         │
│ Docker       │  │ CAS            │
│ Kubernetes   │  └────────────────┘
└──────────────┘

⸻

Execution Fabric

SandTree 将不同执行环境抽象成统一 Resource。

计划支持：

* Local Host
* Windows Sandbox
* Docker Sandbox
* Multipass
* Docker Container
* Kubernetes
* Git Worktree
* Hyper-V
* WSL
* SSH Remote
* Podman
* Incus

Provider 只负责把底层能力转换为 SandTree 的统一模型。

Docker Sandbox API
        ↓
DockerSandboxProvider
        ↓
SandTree Resource Model

上层不直接依赖具体平台。

⸻

Workspace Fabric

不同环境中的文件使用统一 URI。

例如：

local://host/E:/Dev/Star/src/main.rs
worktree://star/STAR-101/src/main.rs
sbx://docker/auth/workspace/src/main.rs
sbx://windows/ai-dev/C:/Dev/Star/main.rs
multipass://integration/home/ubuntu/star/main.rs
docker://postgres/etc/postgresql/postgresql.conf
k8s://dev/default/auth/app/config.toml

UI、Search、RAG、Diff 和 Snapshot 都只操作统一的：

Workspace URI

而不关心文件实际上位于哪个环境。

⸻

Virtual File System

SandTree 在所有 Provider 上构建统一 VFS：

                VFS
                 │
      ┌──────────┼──────────┐
      ▼          ▼          ▼
 Docker SBX   Multipass   Windows SBX

统一操作包括：

list
read
stat
write
remove
search
hash
watch

这样 Agent 也无需理解底层环境差异。

⸻

Snapshot

SandTree 的 Snapshot 不是传统 VM Snapshot。

它是一份开发任务的逻辑状态：

Snapshot
│
├── Task
├── Resource
├── Workspace
├── Git Commit
├── Git Status
├── File Manifest
├── File Hash
├── Agent
├── Services
└── Timestamp

于是可以实现：

Before Agent
    ↓
Snapshot #10
Agent Execution
    ↓
Snapshot #11

然后：

Diff #10 → #11

直接回答：

这个 AI Agent 到底改变了什么？

⸻

Content Addressable Storage

SandTree 不会简单复制所有 Sandbox 文件。

文件首先建立：

Path
Size
mtime
Hash

正文按需读取。

相同内容：

Sandbox A/src/auth.rs
Sandbox B/src/auth.rs
Worktree C/src/auth.rs

如果 Hash 相同：

BLAKE3:8f...

只保存一份内容。

File Instance
     │
     ▼
Content Hash
     │
     ▼
Content Store

这可以显著减少多 Worktree、多 Sandbox 场景下的重复存储。

⸻

Search

第一阶段计划采用：

SQLite
+
FTS5

实现：

* 文件名搜索
* 全文搜索
* Workspace 搜索
* Task 搜索
* Git 状态过滤
* Resource 过滤

未来增加：

Tree-sitter
 ↓
Symbol Index
 ↓
Dependency Graph
 ↓
Embedding
 ↓
RAG

⸻

Intelligence Fabric

SandTree 的长期目标并不是停留在资源管理。

未来可以形成：

Files
 ↓
AST
 ↓
Symbols
 ↓
Dependency Graph
 ↓
Vector Index
 ↓
Agent Context

最终 AI 可以直接询问：

读取 STAR-101 对应 Workspace 中的 auth.rs

SandTree 自动完成：

Task
 ↓
Workspace
 ↓
Resource
 ↓
Provider
 ↓
File

AI 不需要知道文件究竟存在于：

Docker Sandbox
Windows Sandbox
Multipass
Kubernetes

中的哪一种环境。

⸻

Agent Integration

SandTree 可以作为 AI Coding Agent 的统一基础设施入口。

计划支持：

* Codex
* Claude Code
* Hermes
* Cursor
* OpenCode
* Custom Agents

Agent 与 Sandbox 不再是独立对象。

而是：

Task
 ↓
Agent
 ↓
Execution Resource
 ↓
Workspace

⸻

MCP

SandTree 计划提供 MCP Server。

例如：

list_resources
get_topology
get_task
get_workspace
read_file
search_code
exec
snapshot
diff_snapshot

Agent 只需要接入 SandTree MCP。

无需分别学习：

Docker Sandbox
Multipass
Windows Sandbox
Docker
kubectl
Git Worktree

的控制方式。

⸻

Git & Worktree

Git Worktree 是 SandTree 的一等资源。

例如：

Task STAR-101
│
├── Worktree
│   └── wt/star-101
│
├── Sandbox
│
└── Agent

计划支持：

* Worktree discovery
* Branch mapping
* Dirty state
* Ahead / Behind
* Commit tracking
* Diff
* Task binding
* Sandbox binding

SandTree 也可以与 MAGOS 等 Git / Multi-Agent orchestration 系统集成。

⸻

Resource Capabilities

不同 Provider 不需要支持完全相同的功能。

SandTree 使用 Capability 描述资源能力：

START
STOP
EXEC
FILE_LIST
FILE_READ
FILE_WRITE
WATCH
SNAPSHOT
METRICS

例如：

Docker Sandbox
✓ Start
✓ Stop
✓ Exec
✓ File Read
✓ File Write
✓ Metrics

而一个只读远程 Workspace 可以是：

Remote Workspace
✓ File List
✓ File Read
✗ File Write
✗ Exec

Core 和 UI 根据 Capability 自动调整操作。

⸻

Event System

SandTree 内部使用统一事件模型：

SandboxStarted
SandboxStopped
FileCreated
FileModified
FileDeleted
GitChanged
WorktreeCreated
AgentStarted
AgentFinished
ContainerStarted
TaskBound

整体：

Provider
    │
    ▼
 Event Bus
    │
    ├── UI
    ├── Indexer
    ├── Snapshot
    ├── Metrics
    └── Intelligence

⸻

Desktop UI

SandTree Desktop 计划采用四区域结构：

┌────────────┬───────────────┬──────────────┬─────────────┐
│ Projects   │ Topology      │ Files        │ Inspector   │
│            │               │              │             │
│ STAR       │ STAR-101      │ src          │ Resource    │
│ ROPE       │ ├ Worktree    │ ├ auth.rs    │ Git         │
│ GitGit     │ ├ Sandbox     │ └ main.rs    │ Agent       │
│            │ └ Agent       │              │ Health      │
└────────────┴───────────────┴──────────────┴─────────────┘
                  Terminal / Events / Logs

用户可以直接在树上：

Start
Stop
Open
Shell
Snapshot
Diff
Destroy

⸻

Technology Stack

Core:

Rust
Tokio
Serde
Tracing

Desktop:

Tauri
WebView2

API:

Axum
WebSocket

Storage:

SQLite
FTS5
BLAKE3

Git:

git2 / CLI Adapter

Filesystem:

notify

Future:

Tree-sitter
MCP
Vector Search
Graph Index

⸻

Repository Structure

sandtree/
│
├── crates/
│   │
│   ├── model
│   ├── core
│   ├── provider
│   ├── vfs
│   ├── event
│   ├── index
│   ├── store
│   ├── snapshot
│   ├── git
│   ├── task
│   └── api
│
├── providers/
│   │
│   ├── local
│   ├── windows-sandbox
│   ├── docker-sandbox
│   ├── multipass
│   ├── docker
│   └── kubernetes
│
├── apps/
│   │
│   ├── daemon
│   ├── cli
│   ├── desktop
│   └── agent
│
└── integrations/
    │
    ├── mcp
    └── magos

⸻

Roadmap

Phase 1 — Foundation

Local FS
Git Worktree
Docker Sandbox
Multipass

Features:

* Resource discovery
* Tree topology
* File explorer
* Basic execution
* Git mapping

Phase 2 — Workspace

* File indexing
* FTS search
* Hashing
* CAS
* Snapshot
* Diff
* Events

Phase 3 — More Runtimes

* Windows Sandbox Agent
* Docker
* Kubernetes
* WSL
* Hyper-V

Phase 4 — Code Intelligence

* Tree-sitter
* Symbol index
* Dependency graph
* Cross-workspace search

Phase 5 — AI

* MCP Server
* RAG
* Agent bindings
* Context routing
* AI workspace inspection

Phase 6 — AI Development Fabric

Task
 ↓
Environment Scheduler
 ↓
Worktree
 ↓
Sandbox
 ↓
Agent
 ↓
Test
 ↓
Benchmark
 ↓
Snapshot
 ↓
Merge

⸻

Design Philosophy

SandTree 的视觉语言来自两个元素：

Glass

代表：

* 隔离
* 边界
* 可观察
* Sandbox
* Transparency

Sand

代表：

* Disposable environment
* Mutable state
* Temporary workspace
* Sandbox
* Reconstruction

多个玻璃沙体通过树状结构连接：

Sandbox
 ↓
Branch
 ↓
Unified Tree

象征多个隔离环境被统一管理。

⸻

Principles

SandTree 遵循几个核心原则：

Task-first

开发任务是业务中心，Sandbox 只是执行资源。

Provider-independent

Core 不依赖任何具体 Sandbox 平台。

Tree-first

所有开发资源都可以进入统一拓扑。

Workspace-first

文件、Git、Agent 与执行环境属于同一个 Workspace Context。

Observable

Agent 的每次修改都应该能够追踪、比较和解释。

Disposable Infrastructure

Sandbox 可以销毁。

知识、Task、Snapshot 和 Workspace Context 不应该随之丢失。

⸻

Vision

今天：

Developer
 ↓
Docker Desktop
 ↓
Hyper-V
 ↓
Multipass
 ↓
Git
 ↓
k9s
 ↓
AI Agent

每一个工具都是独立孤岛。

SandTree 希望把它们变成：

                    SandTree
                        │
             ┌──────────┼──────────┐
             │          │          │
           Task      Workspace   Agent
             │          │          │
             └──────────┼──────────┘
                        │
                 Execution Fabric
                        │
        ┌───────────────┼───────────────┐
        │               │               │
 Docker Sandbox   Windows Sandbox   Multipass
        │               │               │
        └───────────────┼───────────────┘
                        │
                 Local AI Factory

SandTree 的长期目标：

成为本地 AI 软件工厂的统一 Workspace 与 Execution Control Plane。

⸻

Status

SandTree is currently in early design and architecture stage.

APIs, data models, and provider interfaces may change rapidly.

⸻

License

TBD

⸻

Contributing

SandTree is still forming its foundational architecture.

Contributions around the following areas are especially welcome:

* Sandbox providers
* Virtual filesystem
* Git / Worktree integration
* Tauri UI
* Workspace indexing
* Snapshot systems
* MCP
* AI Agent integrations
* Code intelligence

⸻

SandTree

One tree. Many sandboxes.