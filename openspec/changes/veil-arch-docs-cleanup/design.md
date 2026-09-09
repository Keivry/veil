## Context

现状：功能正确但 `handler.rs` 过大、限流表无界、观测定时未显式单测、文档 6 处可误读。约束：拆分保持行为一致（conformance 回归），文档以 spec 为准，README 为唯一入口。

## Goals / Non-Goals

**Goals：**

- 给出拆分后的模块边界与状态码集中方式，使 apply 可机械执行。
- 给出限流有界与观测显式的最小实现形状。
- 给出 6 处文档修复的精确位置与改后文案方向。

**Non-Goals：**

- 不重排 `service/` 内网关管线（已在 hardening 部分落地）。
- 不引入新运行时依赖。

## Decisions

### D1：handler 按入口拆分，状态码集中注释

**决策**：`src/handler/mod.rs`（勘误：原文 `src/handler.rs`，路径已拆分，语义不变）→ `src/handler/mod.rs`（ re-export ）+ `credential.rs`（`credential/registrations/register/revoke/emergency/approve`）+ `llm/mod.rs`（`llm_proxy/request_rewrite/serve_nonstream/spawn_stream_pump`）；`router.rs` 不变；`error.rs` 头部加状态码表注释（`Pending→202/Auth→403/Unauthorized→401/RateLimited→429/PayloadTooLarge→413/Unavailable→503/NotFound→404/BadRequest→400`）。（注：截至 `bcc6c4e` 已为目录形态 `src/handler/{mod,credential,llm}.rs`，本条为历史决策存档。）

**理由**：凭据与 LLM 错误域正交，混居导致单测必须全量 `AppState`。按入口拆后各模块可独立单测。

### D2：限流表有界 + 双触发清扫

**决策**：`credential_hits/register_hits` 改为 `Mutex<HashMap<String,Instant>>` + `MAX_ENTRIES=4096` + 双触发清扫（`len>1000` 或 `last_sweep>60s` 时清过期键，对齐 Python），`admin` 侧清扫语义在 `admin.rs` 头注释一句声明。`check_rate` 内联清扫，不新增后台任务（请求路径顺带，避免任务泄漏）。

**理由**：`Instant` 键永不过期会长跑膨胀；对齐 Python 语义最小改动；请求路径顺带清扫比后台任务更易验证。

**备选**：独立后台 sweeper 任务——多一任务生命周期管理，不采用。

### D3：观测定时与 KeePass 语义显式化

**决策**：Metrics 加 `wal_checkpoint(TRUNCATE)` 定时调用点（复用既有后台或启动期定时，apply 定）+ `QueueFull 丢最老计 dropped` 单测；`keepass.rs` 头注释声明串行化语义（等价 `semaphore(1)`，并发查询串行）；`registry` 维持 `RwLock` + 注释一句“读多写少，`check_entry_allowed` 已移出锁外”。

### D4：六处文档修复一次收敛

**决策**：

1. 删 `redaction.rs:246-247 off` 注释，以 `Config::is_falsy` 为准，加单测 `off→关闭`。
2. README §4 表头加“是否接入口”列（`10MB` 接入口 enforcement、`8MB` 纯 ceiling 锚点）。
3. README §5 Go 表加“鉴权”列（`registrations` 需 `X-Admin-Token`，旧脚本直读 401）。
4. 端口章节改写为“单进程单监听 `127.0.0.1:8877` + compose 三映射宿主机入口区分”，删“不存在多端口重构”措辞。
5. `approve`/跨片 hold 若选 B 案，README §6 追加 BREAKING 条目（与 approval change 同字）。
6. `scripts/api_conformance.py` 豁免注释与 test-closure change 同字（`admin.html NON_GOAL`）。

## Risks / Trade-offs

- [拆分引入循环依赖] → 编译失败 → `handler/mod.rs` 只 re-export，共享类型留在 `service/mod.rs`，单测先编过再删旧文件。
- [清扫误删未过期键] → 限流逃逸 → 清扫只删 `now-last>window` 键，单测锁定边界。
- [文档改写与 spec 漂移] → 失信 → tasks 设文档-契约比对任务，CI 逐项比对。

## Migration Plan

1. 先 D4 文档（零风险），再 D2 限流（单测），再 D3 观测（定时），最后 D1 拆分（conformance 回归）。
2. 拆分未合入前不删旧 `handler.rs`；合入后旧路径删除单 PR。（注：截至 `bcc6c4e` 已为目录形态，旧单文件已删，本条为历史过程存档。）
3. 回滚：文档/限流/观测均可独立 revert；拆分 revert 即恢复单文件。

## Open Questions

- 无。
