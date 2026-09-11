## Context

现状（见 proposal.md Why）：`rust-rewrite-veil` 已 complete，`src/` 下 `handler.rs`（约 35KB）、`router.rs`、`state.rs` 等分层已存在，但三类缺口仍在规划外：其一转发是否复用 `reqwest::Client` 无单例约定；其二网关转发 handler 职责过粗，改写/非流/流泵混杂导致单测必须端到端；其三部署与文档缺失——顶层无 `README.md`、无 `Dockerfile`/`docker-compose.yml`，admin 限流与 body 上限阈值只散见于旧设计描述，Go `get` 客户端对接无统一说明。

约束：本 change 只写规划 artifacts，不改 `src/` 实现；不碰审计 verdict 与脱敏口径；与 `rust-rewrite-veil` 零重叠；新 change 名固定 `veil-hardening`。

## Goals / Non-Goals

**Goals：**

- 给出 Client 单例与三单元拆分的可实施方案，使 apply 阶段可按任务清单逐项落地并独立验证。
- 给出 README / Dockerfile / compose 的内容结构与校验标准，使文档与部署一次写对。
- 把有争议阈值（10/min vs SSE 并发、10MB vs 8MB）收敛为显式契约，消除“是否有意”的疑问。

**Non-Goals：**

- 不设计审计 verdict 与脱敏 recognizer 的任何语义变更（见 proposal Non-Goals）。
- 不输出 `src/` 级逐行代码 diff，只定模块边界、函数签名形状与错误映射。
- 不引入新外部服务依赖（不引入 Presidio、向量库等重依赖）。

## Decisions

### D1：Client 单例放在应用态，经扩展注入转发单元

**决策**：`reqwest::Client` 在启动期构造一次，放入共享应用态（如 `AppState` 或等价结构），经 `axum::Extension` 注入 `nonstream` / `stream_pump`；禁止在请求路径上调用 `Client::new()`。池参数（空闲超时、连接上限、整体超时）走配置并有默认值，单测以“同一句柄”断言复用。

**理由**：`reqwest::Client` 内含连接池，频繁新建等于丢弃 keep-alive，直接抬高 TLS 握手与延迟。单例是官方推荐用法，改动面最小。

**备选**：

- 每请求新建 Client：实现最省事但性能最差，不采用。
- `OnceLock` 全局静态 Client：可复用但配置不可注入、测试难替换，不采用。

### D2：网关拆为 request_rewrite / nonstream / stream_pump 三单元

**决策**：`request_rewrite` 只做纯改写（输入原始请求体与上下文，输出改写后体与声明头，不触网络）；`nonstream` 只做一发一收转发（输入改写后请求，输出完整响应，错误映射为状态码）；`stream_pump` 只做字节泵（输入上游字节流，输出下游 SSE 帧流，负责终止注入与截断标记，不解析业务语义）。三单元经显式参数传递请求级 `Scope`，不共享可变全局量。

**理由**：纯改写可无网单测；非流可用本地回环断言；流泵可用录制字节流回放。三者错误域正交，混在一起则任何单测都要端到端。

**备选**：

- 保持单一大 handler：改动零成本但不可单测，不采用。
- 按协议再拆九单元（3 协议 × 3 职责）：粒度过细，公共泵逻辑重复，不采用。

### D3：README 为唯一文档入口，Dockerfile 多阶段 + compose 回环三端口

**决策**：顶层 `README.md` 按“部署 / 三因子 / 限流 / 阈值 / Go 对接”五节组织，阈值表与 spec 同字；`Dockerfile` 用 builder + runtime 多阶段，runtime 只留二进制与最小系统库；`docker-compose.yml` 声明 `127.0.0.1:8877/8878/8879` 三端口回环绑定与 `DATA_DIR` 卷挂载，默认不暴露公网。

**理由**：文档分散是本次要解决的问题之一，单入口可防止多源漂移；回环绑定延续旧设计部署约定，默认安全。

**备选**：

- 多 README 分散文档：与目标相悖，不采用。
- 单阶段镜像：构建快但体积大、攻击面大，不采用。

### D4：阈值契约以 spec 为准，差异显式声明为有意

**决策**：admin 通用 `10/min/IP` 与 SSE `5/IP` 并发属不同维度（速率 vs 并发），body 上限 `10MB`（通用 JSON）vs `8MB`（审计 hold/扫描上限类）属不同检查点，均声明为有意设计；超限行为统一为 `429 + Retry-After`（限流）与 `413`（body 超限），响应头与指标在 spec 中锁定。

**理由**：不消除差异、只消除歧义。把“是否有意”的问题变成可验证契约，后续实现只须对齐 spec。

**备选**：

- 统一为单一阈值：会改变已验证行为，属 breaking 且无必要，不采用。
- 不声明留待实现时再定：歧义继续存在，不采用。

## Risks / Trade-offs

- [单例 Client 超时配置不当] → 转发尾延迟上升 → 超时/池上限全部走配置并设保守默认，README 阈值表注明调参指引。
- [流泵拆分后终止注入遗漏] → 下游误判截断 → `terminal_injected` 标记与 `[DONE]` 闭合由 stream_pump spec 锁定，单测用录制流回放覆盖。
- [compose 端口与现网冲突] → 启动失败 → 端口走环境变量覆盖，默认回环三端口，design 迁移计划注明覆盖方式。
- [README 与 spec 漂移] → 文档失信 → tasks 设“文档-契约一致性校验”独立任务，CI 比对阈值表与 spec。

## Migration Plan

1. 按 tasks 顺序先立契约（spec 已在本 change 内就绪），再做单例与三单元重构，最后补 README/Dockerfile/compose。
2. 每步独立验证（单例句柄断言、三单元单测、容器构建启动、文档一致性比对），任一步失败只回滚该步。
3. 回滚策略：单例/拆分改动未合入前不删旧路径；容器化不替代现有直跑部署，只新增一种部署方式。

## Open Questions

- 无。阈值差异已收敛为有意声明；若 apply 阶段实测发现 10MB/8MB 检查点与现网行为不符，以 spec 场景为准提后续 change 修正。
