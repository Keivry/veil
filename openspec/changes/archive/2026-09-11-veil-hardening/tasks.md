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

- [x] 5.1 存量 Go get 客户端直连验证（路径/方法不变），验证：取用与转发全链路通过
- [x] 5.2 三因子齐全与缺失两场景验证，验证：放行/转审/明确拒绝符合 spec
- [x] 5.3 Go 消费阻断流终止验证，验证：收到终止帧且无重试挂起

> 验证记录（2026-09-11，端到端复跑，`scripts/go_interop_e2e.py`，用原仓 venv python）：
> - 前置：本机无 TPM，`start_veil` 内建 `VEIL_ALLOW_MOCK_TPM=1`；临时 kdbx（pykeepass，主密码取 Mock TPM 解封值）提供已解锁库。
> - 网关侧前置（已落地）：`POST /credential` 头缺失时回退读 `body.auth.get_binary_hash/get_binary_secret`（`src/service/credential/auth.rs:22-45`）；`/register-caller` 返回非空 `reg_id`；`/health` 含 `status/unlocked/pending/llm_secrets`。
> - Go 侧前置（已落地）：`internal.ErrMessage` 容忍网关错误体对象（`{"error":{"code","message"}}`）与 Python 字符串双形态，并容忍 `/credential` 成功信封 `{"ok":true,"credential":{...}}` 解包；`internal.ConsumeSSE`/`ConsumeSSEWithRequest` 提供 SSE 消费（含 POST）。
> - 5.1 PASS（取用与转发全链路）：Go 整条目输出 标题/用户名/占位密码/URL；单字段 `--raw` 返回原文 `authcode-abc-123`；`get status` 解析出 `status=ok`/`unlocked`/`pending`/`llm_secrets`；转发以 SDK/HTTP 代表（非流式 200、流式恰一 `[DONE]`）。
> - 5.2 PASS（三因子齐全/缺失）：齐全 Go 放行；错密钥 Go 打印网关拒绝「Secret 校验失败」（不再是「解析响应失败」）；缺 `caller_hash/caller_path`→403；缺 `body.auth`→403；错 Secret→403；已注册路径哈希失配→202 `E_PENDING` 转审；`caller_hash==GET_BINARY_HASH`（token=false）→403 冒用拒绝。
> - 5.3 PASS（Go 消费阻断流终止）：Go `ConsumeSSEWithRequest` 对阻断流（`AUDIT_MODE=block`/`AUDIT_HOLD_MAX_BYTES=16`）三协议均 `terminal=true` 且即时返回（chat `[DONE]`、anthropic `message_stop`、responses `response.failed`，各 ≤0.02s，无重试/挂起）。
> - 汇总：`scripts/go_interop_e2e.py` 共 14 项、失败 0 项（exit 0）。命令：`/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/go_interop_e2e.py`。
> - `get list` 说明：`GET /registrations` 要求管理面鉴权（`X-Admin-Token` 或部署密钥 `X-Get-Binary-Secret`）；Go 存量客户端携带部署密钥即可返回注册列表，无零改动例外。
