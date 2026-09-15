# nonstream-audit-align Specification

## Purpose

统一非流审计与流式同口径（唯一白名单入口 `evaluate_with_whitelist`），修正错误状态下阻断合成边界，使下游状态码与正文不被掩盖，并以测试矩阵锁定流式/非流式 verdict 一致性与审计可观测。

## Requirements

### Requirement: 非流与流式白名单同口径

非流审计 SHALL 经与流式相同的白名单入口 `evaluate_with_whitelist` 判定；`AUDIT_MODE=approve` 且白名单为空时非流 SHALL 与流式一致降级为 block。

#### Scenario: approve 非空白名单 → NeedApproval 透传

- **WHEN** `AUDIT_MODE=approve`、白名单非空、非流响应命中危险调用
- **THEN** 记 pending 且上游响应透传（不断链、不合成阻断体）

#### Scenario: approve 空白名单直调 → block 降级

- **WHEN** 直接以空 `approval_whitelist` 调用非流判定且命中危险调用
- **THEN** 判定为 Block（生产不可达由启动门禁保证，测试注明）

#### Scenario: 流/非流 verdict 对照一致

- **WHEN** 同一危险调用分别经流式与非流路径判定
- **THEN** 两者 verdict 一致（Block 或 NeedApproval 同值）

### Requirement: 错误状态不合成阻断体

非流上游为错误状态（4xx/5xx，除既有非 JSON 502/401 豁免）且审计命中 Block 时，系统 SHALL 保留上游状态码与正文，SHALL NOT 合成 200 阻断体；审计 SHALL 照常记录。

错误状态透传 SHALL 先于响应内容类型（SSE）判定生效：上游 `status >= 400` 时，无论响应 `content-type` 是否为 `text/event-stream`、正文形态是否疑似 SSE 事件流，系统 SHALL 一律按错误体透传**状态码与正文字节**，SHALL NOT 将其改写为 200 假 SSE 流，亦 SHALL NOT 经 SSE 合成路径（输出硬编码 200）输出。SSE 形态分支 SHALL 前置 `status < 400` 守卫，与流式分支既有 `status >= 400` 守卫同口径；Python 对照语义（`_llm.py:6127-6135`）为保留上游状态码，本仓 SHALL 对齐。审计命中 SHALL 照常记录，但 SHALL NOT 因此改变下行状态码与正文。

#### Scenario: 400 JSON 危险调用保留状态

- **WHEN** 上游 400 JSON 体含危险 tool_call，审计模式为 block
- **THEN** 下游收 400 与原始正文；审计日志/指标含该次命中

#### Scenario: 2xx 危险调用仍合成阻断体

- **WHEN** 上游 200 命中 Block
- **THEN** 下游收 200 + `nonstream_block_body`（既有声明行为）

#### Scenario: 4xx 携带 SSE 内容类型不伪造 200 流

- **WHEN** 非流请求上游返回 `status=429` 且响应 `content-type: text/event-stream`
- **THEN** 下游收到 429 与上游正文字节，不出现 200 假 SSE 流

#### Scenario: 5xx 疑似 SSE 正文不改写

- **WHEN** 上游 500 返回形态疑似 SSE 事件的正文
- **THEN** 网关按 500 与原始正文字节透传，不合成 200 SSE 响应

### Requirement: 单入口判定函数

全仓 SHALL 仅保留 `evaluate_with_whitelist` 作为审计判定入口；SHALL NOT 存在忽略白名单的公开判定函数。

#### Scenario: 无绕白名单入口

- **WHEN** grep 审计判定调用点
- **THEN** 所有调用均携带白名单参数，无裸 `evaluate(` 调用

### Requirement: 空体与非 JSON 502 门控边界

非流对话路径的空体/非 JSON 502 门控（`E_EMPTY_BODY` 口径）SHALL 仅在上游 `status == 200` 时生效，与 Python 对照口径一致：`status == 200` 且响应体为空或非 JSON（且未被既有的超限判定或 SSE 形态分支先行处理）时 SHALL 返回 502 `E_EMPTY_BODY`，行为与既有保持一致。`status != 200` 的非错误状态（如 `201`/`204`/`304` 等，均可能合法携带空体）SHALL NOT 被该门控改写为 502，SHALL 按原状态码与正文字节透传。错误状态（`status >= 400`）继续按错误体透传语义处理，SHALL NOT 被本门控改写为 502。更宽的门控（Rust 实现位于 `src/service/llm_gateway/mod.rs:241` 的 `classify_empty`）SHALL 收窄至本边界，SHALL NOT 保留未登记的静默差异。

#### Scenario: 200 空体触发 502

- **WHEN** 上游 200 对话响应体为空或非 JSON
- **THEN** 网关返回 502（`E_EMPTY_BODY`），与既有行为一致

#### Scenario: 非 200 非错误状态空体不被门控改写

- **WHEN** 上游返回 `304`（或 `204`）空体响应
- **THEN** 网关按 304（或 204）状态与空正文透传，不合成 502

#### Scenario: 错误状态不受门控影响

- **WHEN** 上游 404 返回空体
- **THEN** 网关按 404 与空正文透传，不合成 502
