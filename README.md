# veil

> 本机 LLM 脱敏反向代理：请求侧脱敏，响应侧还原，单端口常驻。

## 简介

veil 是常驻本机的脱敏反向代理，站在客户端和 LLM 上游之间，只监听 `127.0.0.1:8877` 一个端口。请求侧的 PII 与凭据被替换成 `__PII_*__` / `__CRED_*__` 占位符；响应侧把上游回显的、由本次请求铸造的占位符还原成原文。未注册/未授权的完整占位符 token 与上游吐出的明文一律逐字节原样透传（不移除、不改写），仅残缺 token 形态被剥离。接入只需把 base URL 指过来，完整工程契约见 `docs/engineering-reference.md`。

## 快速开始

### 本地直跑

部署参数（Matrix homeserver/room、数据目录、LLM 上游）由 TOML 配置文件承载；仅密钥类与进程上下文变量走 env。

```bash
cp examples/veil.toml ./veil.toml   # 按需改 [auth].homeserver / [auth].room_id、[storage].data_dir、[llm]
export VEIL_CONFIG_FILE="$PWD/veil.toml"
export MATRIX_ACCESS_TOKEN=dummy-token
export OBSERVABILITY_ADMIN_TOKEN=0123456789abcdef0123456789abcdef
export VEIL_ALLOW_MOCK_TPM=1
./target/release/veil
```

- 配置文件缺省时 `[storage].data_dir` 为 `/data`；本地直跑请在 TOML 里设成可写路径。
- `MATRIX_ACCESS_TOKEN` 与 `OBSERVABILITY_ADMIN_TOKEN` 均可缺省——缺 Matrix token 时仅审批/凭据同步关闭，缺 admin token（且未设 `[auth].observability_disable`）时 `/_admin*` 全返回 404（管理面未启用）；两 token 均非空且相同时按配置错误拒绝启动，建议 ≥32 字符（不足仅告警）。
- `VEIL_ALLOW_MOCK_TPM=1` 仅限无 TPM 硬件的开发机与 CI，生产必须接 TPM 2.0 并去掉这一项。
- 监听地址硬编码为 `127.0.0.1:8877`，端口不可配；换宿主机入口端口只能走容器映射。

### 容器

```bash
export MATRIX_ACCESS_TOKEN='syt_...'
export OBSERVABILITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
cp examples/veil.toml ./veil.toml
docker compose up -d
```

- compose 把宿主机 `./veil.toml` 只读挂到 `/etc/veil/veil.toml` 并设 `VEIL_CONFIG_FILE`；数据卷父卷 `${DATA_DIR:-./data}` 是**宿主机侧**的卷路径（仅 compose 变量），与配置文件的 `[storage].data_dir`（默认 `/data`）相互独立。
- 三条映射都指向容器内 `8877`；入口端口只区分选路上游，`[llm].default_upstream` 是缺省上游。宿主机端口可经 `PORT_8877`/`PORT_8878`/`PORT_8879` 覆盖，容器内监听恒为 `8877`。
- 无 TPM 硬件时注释掉 `devices` 两行，并补上 `VEIL_ALLOW_MOCK_TPM=1`。

### 健康检查与停止

探活：`curl -sS http://127.0.0.1:8877/health`（无需鉴权），实测返回 8 个字段：

```json
{
  "ok": true,
  "sqlite_ok": true,
  "sqlite_error": null,
  "status": "ok",
  "unlocked": false,
  "pending": 0,
  "llm_secrets": 0,
  "pii_custom_disabled": 0
}
```

`ok:true` 表示进程存活，探针不需要鉴权；`unlocked:false` 是凭据库尚未解锁（不影响 LLM 面），`pending` 是待审批数，`pii_custom_disabled` 是被停用的自定义 PII 规则数。停止：二进制是前台进程，`Ctrl-C` 即退出；容器用 `docker compose down`；`[storage].data_dir` 下 sqlite 与审计日志会自己收尾，无需额外清理。

## 核心配置

配置分两层：**环境变量表**（进程 env 白名单，共 9 个具名变量，见下）与 **TOML 配置文件**（其余设置的唯一来源）。优先级：白名单概念维持 `env 显式 > 文件 > 内建默认`；非白名单概念只由文件承载（同名 env 置位不生效、仅启动期告警）。

### 环境变量表

| 变量 | 默认 | 作用 |
| :-- | :-- | :-- |
| `VEIL_CONFIG_FILE` | 空（不加载） | 可选 TOML 配置文件路径；见下「配置文件」 |
| `RUST_LOG` | `warn` | 日志级别过滤（`EnvFilter`），日志层直读 |
| `HOME` | 进程环境 | 审计策略 `$VAR`/`~/` 展开快照 |
| `VEIL_ALLOW_MOCK_TPM` | 未设置 | 只认字面 `1`，放行 Mock TPM，仅开发机与 CI 使用；生产禁用 |
| `MATRIX_ACCESS_TOKEN` | 空 | Matrix Bot access token；缺省时审批/凭据同步关闭 |
| `OBSERVABILITY_ADMIN_TOKEN` | 空 | `/_admin` 鉴权 token，建议 ≥32 字符且不得与 Matrix token 相同 |
| `VEILCTL_SECRET` | 空（兼容模式） | 三因子部署密钥 |
| `VEILCTL_BINARY_HASH` | 空 | 直调哈希门禁 |
| `PII_VALUE_SAMPLE_HMAC_KEY` | 空 | 值级采样 HMAC key（密钥类建议走 env 注入） |

完整读取面与 compose 边界说明见 `docs/engineering-reference.md` §1。

### 配置文件键表（节选）

非白名单设置的唯一来源为 `VEIL_CONFIG_FILE` 指向的 TOML。完整键表见 `docs/engineering-reference.md` §1，可加载示例见 `examples/veil.toml`。

| 文件键 | 默认 | 作用 |
| :-- | :-- | :-- |
| `[auth].homeserver` / `[auth].room_id` | 空（可选） | Matrix homeserver 与审批房间；缺失即关闭 Matrix 通知/审批（不拒启动） |
| `[auth].matrix_access_token` / `[auth].observability_admin_token` | 空（可 env 注入） | 密钥类；写入文件须 `0600` |
| `[storage].data_dir` | `/data` | sqlite 与审计日志父目录；派生 `db_dir`/`tpm_dir`/`caller_registry_path` |
| `[llm].default_upstream` / `[llm.upstreams."<port>"]` | 空 | 缺省上游与按入口端口选路 |
| `[redaction].enabled` | `true` | 脱敏总开关 |
| `[pii_scope].mode` | `"request"` | 逐请求隔离；`"conversation"` 启用有界的会话级关联 |
| `[limits].sse_frame_hard_bytes` | `8388608`（8MiB） | SSE 单帧/单行硬上限（字节，≥1）；超限 fail-closed 并按协议合成终止帧 |
| `[audit].mode` | `"off"` | `"off"` / `"block"` / `"approve"`；`"approve"` 必须配 `[audit].approval_whitelist` |

### 配置文件（可选）

`VEIL_CONFIG_FILE` 指向一份 TOML；不设置即零行为变化。文件缺失/语法错误/未知键/密钥文件权限不合规一律拒绝启动（fail-closed）。密钥类键建议继续走 env 注入。

### 下游命令执行（可选）

配置文件 `[command]` 分节可向经三因子认证的下游 agent 暴露受控命令：

- `GET /commands` 返回该下游可见的命令目录与参数定义；
- `POST /commands/{id}/invoke` 执行命令（argv 直传、禁止 shell），返回退出码与输出；
- 需审批的命令经 Matrix `✅`/`❎`/`🔓` 落定（`🔓` 持久化 accept-always），默认 `202 + E_PENDING`，
  `[command].block_wait = true` 时阻塞至终态；
- 每次调用写入 `data_dir/commands.sqlite`，可在 `/_admin/commands` 与控制台「命令调用」分区查看。

`[command].enabled = false`（缺省）时命令端点 404、其余行为不变。示例见 `examples/veil.toml`。

## 使用示例

接入时把客户端 base URL 改成 `http://127.0.0.1:8877`，路径与请求体不用动（OpenAI、Anthropic 等 SDK 均支持自定义 `base_url`）。请求 `POST /v1/chat/completions`，body 形如 `{"model":"m","messages":[{"role":"user","content":"我的电话是13812345678，请记住"}]}`。

上游实际收到（实测，中间 system 文案为内建默认，此处截断）：

```json
{
  "model": "m",
  "messages": [
    {
      "role": "system",
      "content": "说明：消息中形如 __PII_*__ 和 __CRED_*__ 的标记是安全网关的敏感信息脱敏占位符，代表被替换的原始值……请原样保留这些占位符……"
    },
    { "role": "user", "content": "我的电话是__PII_1_414b79fe__，请记住" }
  ]
}
```

手机号 `13812345678` 被替换成 `__PII_1_<hex>__`，那条 system 消息由 veil 自动注入（`[redaction].placeholder_prompt` 默认开启）。响应侧按内容形态四路处置（语义细节见 `docs/engineering-reference.md` §6.13）：回显本次请求铸造的占位符则还原成原文；未注册/未授权的完整占位符 token 逐字节原样透出；上游自吐明文原样收到；半截占位符按残缺剥离。

流式 `"stream":true`（SSE）同样生效，脱敏与还原在每个 `data:` 分片生成时完成，`finish_reason` 与 `data: [DONE]` 与直连上游一致。超长 SSE 帧（>1MiB 软限）仍完整交付并标记 `oversize`（仅观测）；超过硬上限 `[limits].sse_frame_hard_bytes`（默认 8MiB，可配）时 fail-closed，按协议合成终止帧，不下发半截 JSON。

## 排障

**日志默认打到 stderr，级别 `warn`；stdout 无输出。** `RUST_LOG` 控制级别与按目标过滤（如 `RUST_LOG=info ./target/release/veil`），非法指令不拒启动、回退默认并在 stderr 说明一行。两类诊断不受 `RUST_LOG` 影响（`off` 也照打）：进程终止类（启动校验失败、端口被占用、TPM 门禁不通过、`serve` 异常退出）与安全配置警告。

持久观测面三个：`[storage].data_dir` 下的 `metrics.sqlite`（60 秒周期落盘）、`audit.log`（仅 `[audit].mode != "off"` 才写，`0600`）、`/_admin/*`（带 `X-Admin-Token` 头请求）。想确认脱敏是否生效，看 `audit.log` 或订阅 `/_admin/events/stream`，两处都是脱敏后内容。常见现象：配置文件非法值/未知键/权限不合规启动即退、stderr 指明原因；KeePass 缺 `.kdbx` 只打 warn、凭据接口 503、LLM 代理不受影响；Matrix 连不上进程照常运行。

## 文档导航

- `docs/engineering-reference.md`：工程契约参考，覆盖部署细节、环境变量表与配置文件键表、限流规则、阈值、传输声明与遗留决策，编号 §1 至 §8 已冻结。
- 文档中出现的 `§编号` 引用，一律指向 `docs/engineering-reference.md` 的同号章节。
