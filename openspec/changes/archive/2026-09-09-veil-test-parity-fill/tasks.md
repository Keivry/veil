## 1. 零覆盖清零（T1/T2）

- [x] 1.1 `rewrite.rs` 单测（T1）：stream_options 键合并/占位符三条件/改写不触网/空白归一开关
- [x] 1.2 `nonstream.rs` 单测（T2）：空体转502/strip 后空体转502/正常文本非502/502-401 语义（原 `llm_empty` 7 项）

## 2. 占位符与流式核心（T3/T4）

- [x] 2.1 占位符回补 34+ 项（T3）：多 system 串/数组/image 块/截断 JSON 透传/非对象透传/三协议真注入集成
- [x] 2.2 流式核心回补（T4）：dual_hold/token 前后缀 hold/PII 数字同尾/single_hold 等价性/fast 慢径/delta 切分

## 3. 审计与凭据（T5/T6）

- [x] 3.1 审计回补（T5）：null 防御/缺 index 跳过/dotdot O(n)/管道优先级/混淆命令/内网放行/跨 chunk 累积/多 index 分组
- [x] 3.2 凭据 E2E（T6）：三因子/health/加解锁/限流/终端直调 403/注册吊销审批链

## 4. vault 与性能（T7/T8）

- [x] 4.1 vault 回补（T7）：空洞跳过/rand8 不可枚举/100 并发 gather 无冲突/同值复用
- [x] 4.2 性能门禁（T8）：1MB<500ms / 100KB<100ms / 1KB<2ms / CJK 粗跳过/dict 增量（CI 失败即拦）

## 5. 可观测/网络/并发（T9/T11/T12）

- [x] 5.1 observability 回补（T9）：model/upstream 联动、series 1h/24h/7d/30d 桶数与空桶零、24h/7d 近似口径、sse 按块计
- [x] 5.2 ipv6 展开 16 项（T11）：毫秒/单位数/日期 T 分隔/`::` 压缩 RFC4291/保留段精确前缀
- [x] 5.3 并发回补（T12）：100 并发注册隔离+复用、hold 跨任务隔离（ContextVar 语义 Rust 等价）
- [x] 5.4 全量门禁 `fmt/clippy/test` 全绿；测试暴露的业务 bug 转交对应 change（本 change 不修生产代码）
