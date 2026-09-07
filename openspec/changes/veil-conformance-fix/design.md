## Context

See proposal.md Why. Current code: `handler.rs emergency_revoke` falls back to `X-Forwarded-For`; `config.rs` only reads `REDACTION_ENABLED`; `block_inject.rs chat_done_frame` prefixes DONE with `event: message`; Anthropic block omits start; `accumulate_usage` sums; Go auth only reads header/`body.secret`; README env table covers 4 vars.

## Goals / Non-Goals

**Goals:**

- P0 安全与兼容以最小 diff 闭环，不改路由表与存储格式。
- 三协议终止符与官方解析器严格兼容。
- Go 5.1-5.3 在本 change 内可勾。

**Non-Goals:**

- 真实 KeePass kdbx + TPM 派生（另立 `veil-keepass-real`）。
- 多端口运行时重构（仅文档声明 + `resolve_upstream` 单测锁定当前语义）。
- `GatewayMetrics` 锁重构（仅降粒度注释 + 计数单测，不换数据结构）。

## Decisions

- 吊销 IP：删除 header 回退分支，`PeerIp` 只来源 `ConnectInfo`；备选“白名单代理”不采用（与限流“不信代理头”契约冲突）。
- DONE 裸帧：`chat_done_frame` 改裸 `data: [DONE]`，`ensure_event_lines` 对 DONE 豁免补 `event:`，其余 data 帧仍补；备选“全帧去 event”不采用（阻断首帧需事件路由）。
- Anthropic start：在 `anthropic_block_frames` 首部补 `content_block_start(index 0, tool_use 空壳)`；备选“客户端容忍缺 start”不可控。
- usage：`merge_usage` 改为按字段 max（`prompt=max(prompt)`，`completion=max`，`total=max`，缺失回退求和仅当双段皆无累计语义时）；快路径加 `input_tokens/output_tokens` 子串；备选“上游类型嗅探”复杂度高不采用。
- Go 兼容：`CredentialBody.auth` 加 `get_binary_hash/get_binary_secret` 可选字段并入现有校验链；错误体加 `error_detail` 字符串镜像、health 加 `status/unlocked` 镜像（加字段不改旧字段）；`entry/field` 缺失在取用路径报 400；备选“改 Go 客户端”违背零改动目标。
- 采样收敛：`Config` 加三字段并复用 `parse` 工具函数，`metrics.rs` 经 `AppState` 读配置；备选“保留 env 直读”可测性差。

## Risks / Trade-offs

- [Risk] 裸 DONE 让依赖 `event: message` 分发的旧客户端漏终帧 → Mitigation：dedupe 单测锁定尾帧位置，conformance 脚本断言 SDK 正常结束。
- [Risk] usage 改 max 低估重传流 → Mitigation：仅 Anthropic 双段用 max，其余协议保持 sum，metrics 单测锁定。
- [Risk] 加字段被严格 schema 客户端拒识 → Mitigation：只加可选镜像字段，不改名不删字段。

## Migration Plan

- 按 tasks 顺序落地，每组 `cargo test`；Go 兼容需 `curl` 三因子两场景 + `api_conformance.py` 14/14；回滚：单 change 未 archive 前直接 revert 本 change 文件，运行时无迁移。
