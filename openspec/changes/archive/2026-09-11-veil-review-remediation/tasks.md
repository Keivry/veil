## 1. Matrix 审批闭环（P0）

- [x] 1.1 接通常驻 sync 循环（since 持久化 + 指数退避 + 启动时间戳过滤），验证：重启复用 token 且断连后自动恢复
- [x] 1.2 接通 `on_reaction→resolve` 五分支（含失配 no-op），验证：批准/拒绝/🔓 三态端到端通过
- [x] 1.3 补 `lock/status/forget` 三指令与自反应/`room_id` 过滤，验证：三指令回显正确、历史事件不重放
- [x] 1.4 `is_mxid_allowed` 改精确匹配 + MXID 非法启动拒 + 四段审批日志，验证：伪造成员被拒、非法白名单拒启动

## 2. TPM 解封正确性（P0）

- [x] 2.1 `createprimary` 补 `-G rsa2048 -g sha256` 并回归跨重启解封，验证：重启后解封成功无完整性错误
- [x] 2.2 `unseal` 改读 `TPM_DIR/seal.*` + `startup_tpm` 注入 KeePass + 解锁缓存，验证：占位路径移除、二次查询不重解
- [x] 2.3 Mock 精确门禁与超时诊断，验证：`VEIL_ALLOW_MOCK_TPM=true` 仍拒启动、无硬件拒启动带指引

## 3. Caller 字段级 ACL（P0）

- [x] 3.1 先加授权拒绝默认收紧（未知 entry/field 转审/拒绝），验证：越权请求被拦
- [x] 3.2 补注册模型（name/desc/entries/allow_mode/old_hash宽限）与变更通知，验证：篡改转审且通知可达
- [x] 3.3 兼容 Go 注册形态映射 + 限流（凭据2s/注册1s）+ 原子落盘0600，验证：限流429与落盘权限符合 spec

## 4. 网关治理与单例 enforcement（P0）

- [x] 4.1 `gateway_serve` 复用 `state.http_client`，删请求路径新建（含 Matrix），验证：代码无 `Client::new` 且复用单测通过
- [x] 4.2 pending 合表/TTL 清扫 + `secret_eq` HMAC 等长替换 + `is_private_ip` 补全/文档限定，验证：孤儿回收有界、IPv6 口径一致
- [x] 4.3 KeePass 锁显式化 + `cargo-udeps` 清死依赖 + 8MB 锚点更名，验证：构建无警告、锚点注释明确不接入口

## 5. 三协议流式 parity

- [x] 5.1 Responses 增量按三级索引保序累积、`done` 校验后审计，验证：三分片工具单 flush 且增量期不放行
- [x] 5.2 Anthropic 按 `index` 字段分桶 + `content_block_stop` 解析，验证：多 index 交错累积正确
- [x] 5.3 占位符分流（字符串 input/非法 system 不注入+warn）+ schema 校验，验证：四形态注入/回退符合 spec
- [x] 5.4 次要事件策略表（thinking/signature/refusal/reasoning/mcp 等透传+审计声明）+ 终止唯一 + 空流兜底，验证：三协议终止帧各恰1个、空流可解析

## 6. PII 自定义兼容

- [x] 6.1 加回 YAML/TXT + 4 别名 + 三变量叠加，验证：示例 YAML 启动加载且指标出现自定义 kind
- [x] 6.2 补约束校验（同名/禁`\b`/禁嵌套/内置重名拒绝/跨文件去重）+ 重叠跳过 + 凭据优先 + 分块 + 超时停用 + CJK，验证：违规规则被拒且告警

## 7. 可观测兼容

- [x] 7.1 加 `range/model/upstream/verdict` 兼容层（或 BREAKING 声明+大盘升级），验证：旧大盘查询非空且新口径等价
- [x] 7.2 存储口径锁定（WAL/0600/ENOSPC/覆盖UPSERT/p95/`is_precise`/摘要脱敏/采样HMAC），验证：磁盘满降级与覆盖不翻倍通过

## 8. 文档契约对齐

- [x] 8.1 修正五矛盾（多端口缺省、`off` 关闭、HASH 独立生效、8MB 子限、health 超集）+ 附注（compose 变量忽略/`<32` 告警/头大小写），验证：新人按文档启动且阈值表与 spec 零漂移
- [x] 8.2 显式三处 BREAKING（脱敏默认开/采样落盘/FIFO→LRU）+ 迁移说明，验证：迁移步骤可执行

## 9. P0 补测

- [x] 9.1 `pii_ipv6_time` 16 项回归，验证：`cargo test ipv6_time` 通过
- [x] 9.2 `audit_approve_stream` 13 项流级（含竞态/早断/溢出），验证：流级批准/拒绝/过期注入通过
- [x] 9.3 `series/model/upstream/pii_value` 查询语义，验证：四窗口与跨日/近似/求和通过
- [x] 9.4 `truncation` TSS01-04 + 真实数据 + 性能锚点（5000名单/增量耗时），验证：截断不造假成功、耗时断言通过

## 10. P1 补测与终验

- [x] 10.1 四误报守卫 + 句末标点/`+86`/`sk-proj`/62-13位卡 + 去抖 + N2/保真/多行/重试 + refusal/pending幂等 + 并发单ask/超时/文案 + 异常回id + malformed/容量分表，验证：对应单测全绿
- [x] 10.2 全量 `cargo test` + `scripts/api_conformance.py` 20 项 + 文档-契约比对，验证：三协议 SDK 全过、漂移零项
