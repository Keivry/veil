# Spec Delta

## MODIFIED Requirements

### Requirement: 空体与非 JSON 502 门控边界

非流对话路径的空体/非 JSON 502 门控（`E_EMPTY_BODY` 口径）SHALL 仅在上游 `status == 200` 时生效，与 Python 对照口径一致：`status == 200` 且响应体为空或非 JSON（且未被既有的超限判定或 SSE 形态分支先行处理）时 SHALL 返回 502 `E_EMPTY_BODY`，行为与既有保持一致。`status != 200` 的非错误状态（如 `201`/`204`/`304` 等，均可能合法携带空体）SHALL NOT 被该门控改写为 502，SHALL 按原状态码与正文字节透传。错误状态（`status >= 400`）继续按错误体透传语义处理，SHALL NOT 被本门控改写为 502。更宽的门控（Rust 实现位于 `src/service/llm_gateway/mod.rs::classify_empty`）SHALL 收窄至本边界，SHALL NOT 保留未登记的静默差异。该指针 SHALL 采用符号锚点（`R6-02`），SHALL NOT 回退为 R5 重构后已指向测试代码的陈旧行号（具体字面量见 change 任务验证命令，此处不复述以免规范自指）。

#### Scenario: 200 空体触发 502

- **WHEN** 上游 200 对话响应体为空或非 JSON
- **THEN** 网关返回 502（`E_EMPTY_BODY`），与既有行为一致

#### Scenario: 非 200 非错误状态空体不被门控改写

- **WHEN** 上游返回 `304`（或 `204`）空体响应
- **THEN** 网关按 304（或 204）状态与空正文透传，不合成 502

#### Scenario: 错误状态不受门控影响

- **WHEN** 上游 404 返回空体
- **THEN** 网关按 404 与空正文透传，不合成 502

#### Scenario: 单入口指针为符号锚点

- **WHEN** 核查本要求对单入口判定函数的定位引用
- **THEN** 引用为符号锚点 `src/service/llm_gateway/mod.rs::classify_empty`（经 `scripts/check_doc_paths.py` 可解析），不再为行号形式
