## Purpose

恢复调用方注册表的授权语义与迁移能力，消除越权放行与误删拒绝，并补齐审批人文链。

## ADDED Requirements

### Requirement: 空授权默认转审

未知 entry/field SHALL 转审批或拒绝，不得默认全拒亦不得默认放行；迁移期 SHALL 先 warn 后拒绝，并给出注册补齐指引。

#### Scenario: 未知字段转审

- **WHEN** 已注册调用方请求未授权字段
- **THEN** 系统转 Matrix 审批而非直接 200

### Requirement: 同值多路径可注册

内容相同但路径不同的脚本 SHALL 允许分别注册；冲突判定 SHALL 只看 path，不得以全局 hash 唯一拒绝。

#### Scenario: 双脚本同内容注册

- **WHEN** 两路径脚本 hash 相同分别注册
- **THEN** 两次注册均成功

### Requirement: Python 格式迁移

启动 SHALL 识别 Python `caller_registry.json`（`version/callers/allowed_entries`）并迁移为当前格式，保留旧文件 `.bak`。

#### Scenario: 存量注册不断链

- **WHEN** 数据目录为旧格式注册表
- **THEN** 启动后旧注册仍有效且旧文件有备份

### Requirement: lock 全清与文案对齐

`lock` SHALL 清未决审批 + pending 表 + 口令缓存 + KeePass 会话；`status/forget` 回显 SHALL 与原仓语义一致（forget 清 token 映射）；注册/吊销/哈希变更 SHALL 恢复 Matrix 审批链，或以 BREAKING 声明直接生效并给出风险说明。

#### Scenario: lock 后无残留审批

- **WHEN** lock 执行后
- **THEN** 未决单与缓存均清空，后续请求重新审批
