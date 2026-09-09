## 1. B1-P0 admin 全矩阵（D1，e2e）

- [x] 1.1 优先级 header 大于 Cookie 大于 query 且仅 SSE 回退
  - Verify: `tests/http_e2e_admin_matrix.rs` 存在，三凭证齐全且 header 有效时按 header 放行
  - Verify: 同文件内仅 Cookie 有效且无 header 时按 Cookie 放行，仅 query 有效时非 SSE 恒 401 而 SSE 放行，边缘含 header 无效但 Cookie 有效则按 Cookie 语义回退
- [x] 1.2 非 SSE 带 query 恒 401 与 token 文件独立性
  - Verify: 非 SSE 管理接口以 `?access_token` 携带有效 token 时恒 401，与 token 值正确性无关
  - Verify: token 经文件加载与环境变量各独立生效，回顾 `tests/http_e2e_credential.rs` 隔离建 app 形态无串扰，边缘含空文件与缺文件行为有别
- [x] 1.3 `OBSERVABILITY_DISABLE=1` 全 404
  - Verify: 置位后 `/_admin/metrics` 与 `/_admin/events/stream` 均 404，与 token 有效性无关
  - Verify: 取消置位后恢复正常鉴权，边缘含值非 `1` 时不触发全 404

## 2. B2-P0 audit_perf 大 body 耗时上限（D2，单测锚）

- [x] 2.1 原 `audit_perf_test` 6 用例等价移植
  - Verify: `tests/audit_perf_bound.rs` 或 `src/service/audit.rs` 内联锚存在，6 用例逐项可映射
  - Verify: 大 body 耗时低于声明宽松上界且判定结论正确，边缘含空体与 8MB 上限附近体各一用例

## 3. B3-P1 非流空体 502 e2e（D3，e2e 加单测）

- [x] 3.1 空体与 strip 后空体转 502
  - Verify: 上游空体与空白 strip 后空体 e2e 均返回 502 且错误码为 `E_EMPTY_BODY`，不透传空 200
  - Verify: 非空体不受影响仍按原语义透传，边缘含仅换行与仅空格体均判空
- [x] 3.2 `bytes_written==0` 守门单测
  - Verify: 守门单测存在，零字节写入走 502 分支
  - Verify: 非零字节写入不误判，边缘含单字节体通过

## 4. B4-P1 PII 回归 30 余断言（D4，单测）

- [x] 4.1 IPv6 时间戳与前导零 IPv4 与句末句号
  - Verify: `src/service/pii/` 内联单测存在，IPv6 时间戳混合不误杀，前导零 IPv4 按归一口径处理
  - Verify: 句末句号保留在占位符外，边缘含句号紧贴占位符与多句号各一用例
- [x] 4.2 URL 订单号与保留段豁免与 CJK 边界
  - Verify: `?id=` 订单号按规则脱敏，保留段命中豁免不脱敏
  - Verify: CJK 边界不断字误杀，边缘含中英混排与 URL 编码形态各一用例
- [x] 4.3 `lru_cache` 与四回归文件一对一映射
  - Verify: 四回归文件每项在 tasks 登记移植位置，无第三状态
  - Verify: 缓存命中复用与逐出语义单测通过，边缘含容量 1000 边界行为断言
  - 登记：`detector.rs::b4_mixed_forms_regression`（时间戳/前导零/订单号/编码/CJK）；
    `chunk.rs::b4_trailing_punct_span_edges`（句末标点 span 边缘，既有 `trailing_punct_stripped_still_matches`/`order_url_param_not_flagged_as_bank_card` 为同文件既有锚）；
    `scope.rs::b4_lru_hit_reuse_and_thousand_boundary`（命中复用/1000 边界/逐出，既有 `request_table_capacity_split_lru_eviction`/`vault_parity_tests::t7_*` 为同文件既有锚）；
    `custom.rs::b4_cjk_mixed_and_reserved_edges`（保留段/CJK 混排/字典边界）

## 5. B5-P1 metrics 六语义（D5，单测加 e2e）

- [x] 5.1 QueueFull 丢最老与 flush 去抖 2 秒
  - Verify: `src/service/metrics/aggregate.rs` 归属单测存在，满队列丢最老且最新保留可查
  - Verify: 2 秒内多次触发只 flush 一次，边缘含恰 2 秒边界行为断言
- [x] 5.2 hourly 与 daily 窗口与 model 白名单
  - Verify: hourly 与 daily 窗口键语义单测通过，跨窗不串扰
  - Verify: model 白名单含 `:@` 形态通过，非白名单回退 `unknown`，边缘含空 model 与超长截断各一用例
- [x] 5.3 upstream 与 PII 双计与 SSE 15 秒快照形状
  - Verify: 同一事件计入 upstream 与 PII 双口径且不双计总量，单测断言
  - Verify: SSE 15 秒快照 e2e 字段形状与 `series` 一致，边缘含空窗快照形状不断言崩溃

## 6. B6-P1 vault 四语义（D6，单测）

- [x] 6.1 `rand8 token_hex` 不可枚举与 `gap_skip` 空洞复用
  - Verify: 批量生成无碰撞且无可预测序列断言存在
  - Verify: 删除后空洞被复用且数据一致，边缘含连续删除多空洞复用顺序断言
- [x] 6.2 fuzzy 非法拒绝与 BOM 与 depth 与三包装器
  - Verify: fuzzy 非法形态矩阵均被拒绝且 vault 状态不变
  - Verify: BOM 剥离、depth 超限截断不崩、三包装器逐项解析通过，边缘含嵌套包装器一用例

## 7. B7-P1 限流三语义（D7，e2e）

- [x] 7.1 TCP 远端不采信代理头与 `unknown` 桶
  - Verify: 伪造 `X-Forwarded-For` 的真回环 e2e 仍按 TCP 远端计数拒绝
  - Verify: 缺 model 形态落 `unknown` 桶且计数隔离，边缘含 `X-Real-IP` 伪造同样不采信
- [x] 7.2 SSE 断开 cleanup
  - Verify: SSE 建连断开后并发槽释放，新连接可建连
  - Verify: 并发打满 5 后第 6 建连被拒但已建连接不受影响，边缘含客户端异常断开一用例

## 8. B8-P2 审批三语义（D8，e2e 加单测）

- [x] 8.1 `AUTO_APPROVE` 三态
  - Verify: `true` 放行、`false` 拒绝、`none` 转 Matrix 审批三 e2e 各一用例
  - Verify: 非法值拒启动不断言放行，边缘含大小写变体行为断言
- [x] 8.2 非 full 降级阻断与篡改转 pending 202
  - Verify: 非 full 入口下 `approve_hash_change` 返回鉴权失败且不执行变更
  - Verify: 已注册篡改哈希返回 202 建单 pending，边缘含未注册篡改同样 pending 不直拒

## 9. B9-P2 deny 摘要双形态（D9，审计断言）

- [x] 9.1 Bearer 形态与键值 JSON 形态
  - Verify: Bearer 头形态 deny 摘要脱敏记录且无明文，字段齐全
  - Verify: 键值 JSON 形态 deny 摘要同样脱敏且形态字段齐全，边缘含双形态齐全时各记各摘要不混淆

## 10. B10 flaky 加固（D10，加固）

- [x] 10.1 三处 5ms 分片改有界等待
  - Verify: `tests/http_e2e_sse_loop.rs:76`、`truncation_matrix:60`、`sentinel_sdk_replay.rs:79` 改为 readiness 轮询首选或 20ms 等待，CI 慢机三轮重跑通过
  - Verify: 总时长增量有界且单测注释注明等待策略，边缘含轮询超时熔断行为断言
  - 落地：三处均取 20ms 固定有界等待（mock 单向推送无客户端 readiness 可轮询；策略已注于各 mock 处注释）；三轮重跑 21/21 通过
- [x] 10.2 两处复核
  - Verify: `truncation:62` 50ms 复核结论已记录，不足够则同步加固
  - Verify: `src/service/audit.rs:1086` 线程 sleep 链式上限复核结论已记录，叠加超标则设上限熔断
  - 复核结论：`truncation:62` 50ms 为单次分片间隔（非循环），三轮重跑 2/2 通过，足够，保留；
    `audit.rs:1086` 为单次重试（失败→sleep 50ms→再试一次→熔断返回），每调用至多 +50ms、无循环叠加，不超标，无需熔断上限
