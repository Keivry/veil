# Spec Delta

## ADDED Requirements

### Requirement: 流式透传上游响应头多值保留

系统 SHALL 在流式错误体/非 SSE 透传路径（`src/handler/llm/dispatch.rs::stream_upstream_passthrough`）将上游响应头克隆到下游 `HeaderMap` 时逐值保留同名多值头（`append` 语义），SHALL NOT 因 `insert` 折叠为末值（`R6-03`）。`x-veil-*` 内部头的剔除与网关自置头（`x-veil-protocol` 等）的覆盖语义 SHALL 保持不变，SHALL NOT 因多值保留而被上游同名头覆盖。HOP 过滤与解码配对判定 SHALL 保持按去重键计数（多值键计一次），不因多值改判。

#### Scenario: 上游错误透传保留多值头

- **WHEN** 上游错误（`status >= 400`）响应携带两条同名多值头（如两条 `warning`）且进入 `stream_upstream_passthrough` 透传路径
- **THEN** 下游 `get_all` 得两条同值头，SHALL NOT 只剩末值

#### Scenario: 内部头隔离不受多值影响

- **WHEN** 上游响应含 `x-veil-debug: leak` 且含另一条同名非内部多值头
- **THEN** 下游不含任何 `x-veil-*`，`x-veil-protocol` 为网关自置值
