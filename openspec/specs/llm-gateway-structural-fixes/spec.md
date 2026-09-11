# llm-gateway-structural-fixes Specification

## Purpose
消除三协议网关处理后破坏请求/响应结构、语义与工具调用的 7 类风险，使脱敏还原与审计与官方 API 规范一致。

## Requirements

### Requirement: Responses instructions 注入与 input 分流

系统 SHALL 对 `responses.instructions` 执行与 `input` 同等的占位符注入；`input` 为 string 或 array 时 SHALL 分别按字符串/首条前插处理；非法形态 SHALL 不注入并 warn。注入后 SHALL 做 schema 校验，失败回退不注入。

#### Scenario: instructions 含 PII 被脱敏

- **WHEN** `instructions` 含手机号
- **THEN** 上游收到的 `instructions` 已脱敏且结构不变

### Requirement: restored_spans 跳过防二次掩码

还原后新检出注册占位符时 SHALL 跳过 `restored_spans`（刚还原出的请求明文区间），不得将其二次掩码为响应 token。

#### Scenario: 请求明文往返不变

- **WHEN** 响应原文含请求已还原的明文
- **THEN** 该明文保持明文，不被套上 `__PII_*__`

### Requirement: 非流补 tool 提取与审计

非流式响应 SHALL 提取三协议 tool 调用（chat `tool_calls`、anthropic `tool_use`、responses `function_call`）并执行 `audit::evaluate`；阻断时 SHALL 返回协议正确的 block 体；通过才放行。

#### Scenario: 非流危险调用被拦

- **WHEN** 非流 responses 含 `rm -rf /` 的 function_call
- **THEN** 系统返回 block 体而非原文

### Requirement: Anthropic 按外层 index 分桶

Anthropic 累积 SHALL 取外层 `content_block_start.index`/`content_block_delta.index`，不得取内层 `content_block/delta.index`；缺失回退枚举下标。

#### Scenario: 多 tool 交错不串桶

- **WHEN** 两个 tool_use 块交错到达
- **THEN** 各自 `partial_json` 独立累积且审计各判各

### Requirement: 完成标记按 index 而非全局

`content_block_stop/item_done` SHALL 只审计并清理对应 index 的 `arg_buf`，不得标记全局完成；全局完成仅由 `message_stop/completed` 触发。

#### Scenario: 第二 tool 不逃逸

- **WHEN** 第一块 stop 后第二块 tool_use 到达
- **THEN** 第二块仍被审计，不直接 Approved

### Requirement: BOM/DONE/残余/终端去重

BOM SHALL 剥离后判 `[DONE]` 与 JSON 解析；残余 SHALL 丢弃而非 `data:` 直发；终端 SHALL 经 `dedupe_terminal_frames` 去重多 `[DONE]/message_stop`，保持恰一终止帧。

#### Scenario: BOM+终止正确收尾

- **WHEN** 流以 `﻿data: [DONE]` 到达
- **THEN** 下游恰收到一个终止帧

### Requirement: usage 口径与深炸弹守卫

usage 累积 SHALL 统一为 `max` 口径并文档化；`json_walk` SHALL 设深度/长度守卫，超限回退原串不栈溢出。

#### Scenario: usage 不双计

- **WHEN** 上游分片累计 usage 到达
- **THEN** 指标取 max 而非 sum

#### Scenario: 恶意嵌套不崩

- **WHEN** 请求含超深嵌套 JSON
- **THEN** 系统回退原串转发，进程不崩
