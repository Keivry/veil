## Purpose

测试矩阵相对 Python 42 文件基线闭环：截断/SDK/流边界/凭据/可观测/性能锚全覆盖，BREAKING 逐项验收或接受风险，无静默缺口。

## ADDED Requirements

### Requirement: 截断矩阵四模式闭环

系统 SHALL 以 e2e 锁定 TSS01 静默丢弃、TSS02 开环、TSS03 tool 丢弃、TSS04 Responses 合成 `failed`，真实 reasoning/toolcalls SHALL 无伪造成功。

#### Scenario: tool 中截断不伪造完成

- **WHEN** tool_calls 参数截断不全
- **THEN** 整把丢弃且不合成 `success/completed`，流以 fail-closed 闭合

### Requirement: SDK 级三协议还原断言

系统 SHALL 对 thinking 签名、`tool_use` 跨帧累积、`CR-only` 双路径、`error` 插帧、`usage` 累计、`stop_sequence` 回显逐项移植或显式豁免。

#### Scenario: 签名块不透明透传

- **WHEN** 流含 `thinking_delta + signature_delta`
- **THEN** 网关不改写两字段且多轮回传可用（字节一致断言）

#### Scenario: tool 输入提交点正确

- **WHEN** `input_json` 分片跨事件到达
- **THEN** 仅在 `content_block_stop` 后可 parse，中途不做逐包校验

### Requirement: 流泵边界可验证

系统 SHALL 覆盖重试、`n2` 隔离、多 `data:`、`retry:` 非法、`refusal` 重组、BOM+comment、flush 幂等、hold 溢出/abort/竞态/清理、deny 转发、`done` 回退。

#### Scenario: hold 溢出 fail-closed

- **WHEN** 审计 hold 累积超 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 丢弃并注入阻断帧，不透出危险原文

### Requirement: 凭据分支与可观测语义覆盖

系统 SHALL 覆盖解锁超时/并发单 ask/三文案/双删，SSE 计数/过滤/`series` 四窗/归一/跨日/ENOSPC SHALL 有断言。

#### Scenario: 并发解锁单 ask

- **WHEN** 双解锁请求并发到达
- **THEN** 仅一次 Matrix ask，另一方等待同一结果

#### Scenario: 旧过滤全局口径可观测

- **WHEN** 调用 `metrics/events?model=&upstream=`
- **THEN** 返回全局口径且附 `deprecated + compat` 标注

### Requirement: BREAKING 逐项验收或接受风险

系统 SHALL 对 6.1–6.4 与收敛项逐项迁移测试或 `ACCEPTED RISK` 标注，不留第三状态。

#### Scenario: 默认开不误伤可回退

- **WHEN** 显式 `REDACTION_ENABLED=0`
- **THEN** 请求零值透传，与原仓行为一致

## ACCEPTED RISK（显式豁免）

- `admin.html` 静态页：Non-Goal，不交付不测试（与 `observability-admin` spec 同字）。
- `CREDENTIAL_PROXY_DEBUG_DIR` 四件落盘：不恢复（落盘即涉密，需配套脱敏，见 README §7.4）。
