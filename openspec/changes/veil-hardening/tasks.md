## 1. Client 单例

- [x] 1.1 定义 Client 单例注入形状（启动期构造、共享态持有、Extension 注入），验证：代码评审确认无请求路径新建
- [x] 1.2 增加单例复用单测（两次转发同一句柄），验证：`cargo test client_singleton` 通过
- [x] 1.3 增加超时与池上限配置项及默认值，验证：缺省启动与覆盖启动各一次均正常

## 2. 网关三单元拆分

- [x] 2.1 抽取 `request_rewrite` 纯函数并加无网单测，验证：断网条件下单测仍通过
- [x] 2.2 抽取 `nonstream` 一发一收单元并加回环单测，验证：成功与超时两场景状态码符合 spec
- [x] 2.3 抽取 `stream_pump` 字节泵并加录制流回放单测，验证：正常收尾与阻断注入终止两场景通过

## 3. 契约声明

- [x] 3.1 落实 admin 限流契约（10/min + 429 + Retry-After、按远端计数），验证：超限场景返回头符合 spec
- [x] 3.2 落实 SSE 并发契约（5/IP、拒绝不影响已建连接），验证：6 并发场景第 6 条被拒、前 5 条正常
- [x] 3.3 落实 body 上限分级契约（413、10MB vs 8MB 差异说明），验证：超限场景状态码与文档说明一致

## 4. 文档与部署

- [x] 4.1 编写顶层 README 五节（部署/三因子/限流/阈值/Go 对接），验证：新人按文档可启动并通过健康检查
- [x] 4.2 新增多阶段 Dockerfile 并构建镜像，验证：构建成功且 runtime 无工具链
- [x] 4.3 新增 docker-compose.yml（回环三端口 + 卷挂载）并启动，验证：三端口回环可达、公网不可达
- [x] 4.4 文档-契约一致性校验（README 阈值表 vs specs），验证：逐项比对零漂移

## 5. Go 对接验证

- [ ] 5.1 存量 Go get 客户端直连验证（路径/方法不变），验证：取用与转发全链路通过
- [ ] 5.2 三因子齐全与缺失两场景验证，验证：放行/转审/明确拒绝符合 spec
- [ ] 5.3 Go 消费阻断流终止验证，验证：收到终止帧且无重试挂起

> 验证记录（2026-09-07，未改 Go 二进制直连，注意：三项保持未勾，原因见下；未改 Go/Rust 协议、未提交）：
> - 基线：`scripts/api_conformance.py` 三协议 SDK 14/14 通过（chat/anthropic/responses 流式·非流式·tool + 三阻断相）。
>   前置条件：工作区脏改动（`ADMIN_TOKEN_MIN_LEN` 未定义等）致 `cargo build` 失败，验证改用 `HEAD(fcc881f)`
>   隔离 worktree 构建；本机无 TPM，需 `VEIL_ALLOW_MOCK_TPM=1`（脚本未内建，为既有缺口）。
> - 5.1（阻塞）：路径/方法零改动可路由（`POST /credential`、`GET /registrations`、`POST /register-caller`、
>   `POST /revoke`、`GET /health` 均存在）；但取用全链路不通过——`get credential`（`internal/proxy.go`
>   `FetchCredential` 纯 body POST，不带任何头）恒 403：终端直调→403 `E_AUTH`「调用方冒用 get 自身哈希直调，
>   拒绝」；脚本上下文→403 `E_AUTH`「Secret 校验失败」（`body.auth.get_binary_secret` 被网关忽略，
>   网关只认 `X-Get-Binary-Secret` 头/`body.secret`，而 Go 取用从不发头）。另 Go 无法解析网关错误体
>   （网关 `{"error":{"code","message"}}` 对象 vs Go `error string`，报「解析响应失败」掩盖真实信息）；
>   `get status` 零值展示（网关 `{ok,sqlite_ok,sqlite_error}` vs Go `{status,unlocked,pending,llm_secrets}`）；
>   `get list` 恰好互通（`X-Get-Binary-Secret` 头被网关接受，空列表可解析）。Go 客户端无 LLM 转发功能，
>   转发仅能以 curl 经网关验证（非流式 200、流式帧正常）。→ 保持未勾。
> - 5.2（阻塞）：网关侧逐项符合 spec——缺 `body.auth`→403「caller_hash/caller_path 必填」；错 secret→403
>   「Secret 校验失败」；缺 `X-Get-Binary-Hash` 头→脚本上下文 403「Secret 校验失败」（先于头检查）；
>   终端直调（`caller_hash==GET_BINARY_HASH`）→403「冒用拒绝」；头体一致+已注册+批准→穿透鉴权至
>   503 `E_UNAVAILABLE`「KeePass 未解锁」（生产二进制 `MockKeePass` 恒锁定，放行只能验到此层）；
>   头体不一致未注册→202 `E_PENDING`「已转 Matrix 人工审批: hash_mismatch」（符合「放行或转审」）；
>   Go 多余字段（`entry/field/token/auth.get_binary_*`）被静默忽略、无协议错误。但未改 Go 二进制发不出
>   「齐全且头体一致」的取用（取用路径不发头），故端到端放行不可达。→ 保持未勾。
> - 5.3（阻塞）：线级三协议阻断终止均即时闭合（0s，无挂起）：chat→`[blocked: audit-hold-overflow]`+唯一
>   `data: [DONE]`、无 `rm -rf` 泄漏；anthropic→`message_stop(reason=audit-hold-overflow)`+
>   `content_block_stop`、无泄漏；responses→`response.failed`。但 Go 客户端无任何 SSE 消费代码
>   （`get/` 内无 `event-stream` 相关实现，全为一发一收 unary 调用），「Go 消费阻断流」场景不可执行；
>   相应地 Go 也不可能重试/挂起。→ 保持未勾。
> - 互操作缺口与适配建议（均不擅自改 Go/Rust 协议，待立项决策）：(1) Go `FetchCredential` 补发
>   `X-Get-Binary-Hash/Secret` 头（`AuthHeaders()` 已有实现，仅取用路径未用）或网关兼容读
>   `body.auth.get_binary_hash/secret`；(2) 错误体形态统一（网关 `error` 对象 vs Go `error string`，
>   至少一方兼容）；(3) `/health` 形态统一（`ok/sqlite_*` vs `status/unlocked/pending/llm_secrets`）；
>   (4) `/register-caller` 形态统一（网关顶层 `caller_path/caller_hash/source` vs Go
>   `name/script_path/script_hash/entries/allow_mode`）；(5) `CredentialBody` 丢弃 `entry/field`
>   （网关按 `caller_path` 取凭据，与 Go 按条目/字段取用语义不同）；(6) `api_conformance.py`
>   内建 `VEIL_ALLOW_MOCK_TPM=1` 回退或显式报错指引。
