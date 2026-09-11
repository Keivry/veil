## Why

`rust-rewrite-veil` 已完成（35/35 任务，状态 complete），Rust 网关骨架与三协议合规修正已落地。但收尾的性能/部署/文档工作尚未进入任何 change：转发链路仍存在每请求新建 `reqwest::Client` 的连接池浪费风险，`gateway_serve` 级 handler 承担改写加非流加流泵三职责难以单测，顶层缺 README（部署/三因子/限流/阈值无统一入口），缺 Dockerfile 与 compose（回环三端口无声明式部署），admin 限流与 body 上限阈值（10/min 通用 vs SSE 5/IP 并发、10MB vs 8MB）无显式契约，Go `get` 客户端对接说明散落。此时开增量 change 承接这些工作，可与已完成的重写 change 零重叠。

## What Changes

- **性能 1，reqwest Client 复用单例**：转发上游的 `reqwest::Client` 改为进程级单例（连接池复用），不再按请求构造；超时/池上限走配置，单测断言多请求共享同一池句柄。
- **结构 1，`gateway_serve` 拆三单元**：把网关转发 handler 拆为 `request_rewrite`（请求改写）/ `nonstream`（非流转发）/ `stream_pump`（流式泵）三个可独立单测的单元，职责边界与错误映射显式化。
- **文档 1，顶层 README**：新增顶层 `README.md`，统一说明部署方式、三因子鉴权、限流规则、各阈值含义， Go 客户端对接另见专用说明。
- **部署 1，Dockerfile + compose**：新增多阶段 `Dockerfile` 与 `docker-compose.yml`，声明回环三端口（`127.0.0.1:8877/8878/8879`）与卷挂载约定。
- **契约 1，admin 限流与 body 上限声明**：把 admin 通用 `10/min/IP`（超限 429 + `Retry-After`）vs SSE `5/IP` 并发、请求体 `10MB` vs `8MB` 上限的取值与差异理由写进契约，明确是否为有意设计，行为不一致处以 spec 为准。
- **对接 1，Go get 客户端说明**：在 README 或独立小节中声明 Go `get` 客户端对接方式（路径/方法/鉴权头/三因子字段/SSE 语义零改动可直接对接）。

## Capabilities

### New Capabilities

- `http-client-singleton`：reqwest Client 进程单例复用、池配置与可观测约定。
- `gateway-pipeline-units`：request_rewrite / nonstream / stream_pump 三单元职责、输入输出与错误映射。
- `deploy-docs`：顶层 README 内容结构、Dockerfile 多阶段构建、compose 回环三端口与卷约定。
- `admin-ratelimit-contract`：admin 限流（10/min 通用、SSE 5/IP 并发、429 + Retry-After）与 body 上限（10MB vs 8MB）契约声明。
- `go-client-interop`：Go get 客户端对接说明（路径/鉴权/三因子/SSE 语义）。

### Modified Capabilities

- 无。本 change 不修改任何既有 spec 需求；`openspec/specs/` 当前为空，`rust-rewrite-veil` 的行为契约保持不动。

## Non-Goals（显式）

- 不碰审计 verdict 判定口径（block/approve 语义、hold/截断三态维持原样）。
- 不碰脱敏口径（凭据/PII 占位符形态、recognizer 集合、豁免与 ReDoS 策略维持原样）。
- 不改 `src/` 下任何实现代码；本 change 只交付规划 artifacts，实现留待 apply 阶段。
- 不改 `openspec/changes/rust-rewrite-veil/` 内任何文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-hardening/` 下 proposal.md、design.md、specs 五份 spec.md、tasks.md；apply 阶段才新增顶层 `README.md`、`Dockerfile`、`docker-compose.yml` 与 `src/` 内重构。
- **影响系统**：转发性能（连接复用）、网关可测试性（三单元拆分）、部署方式（容器化）、文档入口（README）、admin 可观测契约、Go 客户端对接确定性。
- **依赖**：`reqwest` 连接池、`tokio` 运行时、`axum` body 限制层；部署依赖 Docker 多阶段构建。
