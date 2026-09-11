## Purpose

消除 README、spec 与代码三源分叉，使部署与阈值文档一次写对且可校验。

## ADDED Requirements

### Requirement: 矛盾修正

文档 SHALL 与实现一致：多端口选路上游声明缺省唯一生效（或补透传实现）；`PII_PLACEHOLDER_PROMPT` 关闭集 SHALL 含 `off`；`GET_BINARY_HASH` SHALL 声明独立生效；8MB SHALL 声明为策略子限 ceiling（入口 enforcement 仅 10MB）或补第二检查点；`/health` SHALL 文档化 `status/unlocked` 超集字段；compose 专用变量二进制忽略、`admin_token<32` 仅告警、`Retry-After` 大小写不敏感 SHALL 各加注一行；阈值表 SHALL 与 spec 同字并加 CI 比对。

#### Scenario: 按文档启动

- **WHEN** 新人按 README 设置环境并启动
- **THEN** 行为与文档一致，健康检查输出与示例字段对齐

#### Scenario: 开关可关

- **WHEN** 设置 `PII_PLACEHOLDER_PROMPT=off`
- **THEN** 系统不注入占位符说明
