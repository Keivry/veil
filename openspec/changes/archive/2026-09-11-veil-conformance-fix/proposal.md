## Why

Rust 重构双 change 自测与第三方审查发现 P0 级安全/兼容断裂与三协议终止污染：紧急吊销信任 `X-Forwarded-For`、脱敏开关重命名致原仓配置失效、Chat `[DONE]` 附加 `event:` 破坏严格解析器、Anthropic 阻断缺 `start`、usage 累加双计、Go 客户端恒 403。若不修复，生产不可上线，`veil-hardening 5.1-5.3` 无法闭环。

## What Changes

- 去除 `emergency_revoke` 对 `X-Forwarded-For` 的回退，只认 TCP 远端；补回归单测。
- 兼容原仓 PII 环境变量：`PII_REDACTION_ENABLED` 为 `REDACTION_ENABLED` 别名、`PII_RESPONSE_SIDE/FUZZY/HARDENING` 恢复语义、`PII_CUSTOM_*` 缺文件/解析失败拒启动；`PII_VALUE_SAMPLE_*` 收敛进 `Config`。
- Chat 终止帧回归官方形态：裸 `data: [DONE]` 不补 `event:`，去重仍保恰 1 个；阻断首帧保留 `event: message` 但尾帧裸 DONE。
- Anthropic 阻断补 `content_block_start`；Responses 补 `incomplete/error` 映射到 `failed` 闭合；usage 流式累加改单调 max（`message_start` 输入 + `message_delta` 输出分别取 max，不求和）；`extract_usage_stream` 快路径兼查 `input_tokens/output_tokens`。
- Go 互操作 6 缺口闭环：网关兼容读 `body.auth.get_binary_hash/secret`、错误体/健康/注册形态双向兼容或显式 400 文档化、`entry/field` 不再静默丢弃（缺失报 400 指引）。
- 文档与可观测：README 补 env 全表（PII/AUDIT/TPM/LLM）、`admin.html` 缺失声明、多端口语义声明、`VEIL_ALLOW_MOCK_TPM` 指引；`GatewayMetrics` 高争用路径降锁粒度说明。
- 测试：补紧急吊销伪造头、DONE 裸形态、Anthropic start、usage 双段、Go 取用头体一致、PII 自定义 fail-closed 6 组回归；`api_conformance.py` 内建 mock-TPM 回退并入 CI。
- Non-Goal：真实 KeePass kdbx + TPM 派生主密钥另立 `veil-keepass-real` change，本 change 仅强化 `MockKeePass` 生产阻断文档，不接入 kdbx 依赖。

## Capabilities

### New Capabilities

- `security-compat-fix`: 紧急吊销 IP 来源、PII 环境变量兼容、采样配置收敛、TPM/DB 接线约束。
- `protocol-termination-fix`: 三协议终止帧形态、usage 口径、incomplete/error 闭合。
- `go-interop-contract`: Go/网关形态兼容与错误指引，闭环 `veil-hardening 5.1-5.3`。
- `docs-test-closure`: README/阈值/env 文档闭环与回归测试门禁。

### Modified Capabilities

- 无（`rust-rewrite-veil` 已 complete 不重写，`veil-hardening` 未勾 5.x 由本 change 承接闭环，不直接改原 change 文件）。

## Impact

- 影响 `src/handler/mod.rs`（吊销 IP）、`src/config.rs`（env 别名/采样收敛）、`src/service/block_inject.rs`（终止帧）、`src/service/llm_gateway/mod.rs`（usage/tool/conv）、`src/service/mod.rs`（Go 兼容）、`README.md`、`scripts/api_conformance.py`（勘误：原文 `src/handler.rs`/`src/service/llm_gateway.rs`，路径已拆分，语义不变）。
- **BREAKING**：Chat 尾帧去 `event:`、缺 `entry/field` 由静默忽略改为 400（需 Go 侧同步，见 go-interop spec）。
- 不碰 `openspec/changes/rust-rewrite-veil/*` 与 `veil-hardening/*` 原文件；KeePass 真后端另立 change。
