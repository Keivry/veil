## T1. T-M1 metrics 筛选滚动（D1）

- [x] T1.1 单测锁 QueueFull/flush/窗口/白名单
  - Verify：丢最老、2s 去抖、跨窗不串扰、` :@` 通过/non白名单回退 `unknown` 单测通过
  - Verify：`cargo test metrics` 通过
- [x] T1.2 e2e 锁 series 筛选与空窗快照
  - Verify：`tests/http_e2e_metrics_filter.rs` 存在，`granularity/model/upstream` 与空窗形状断言通过

## T2. T-M2 NonDialog 透传 e2e（D2）

- [x] T2.1 新增透传 e2e
  - Verify：`/v1/models` 原文转发 + `nondialog_passthrough` 计数 + 无用量/审计/还原断言通过

## T3. T-M3 并发与 T-M4 稳定 e2e（D3）

- [x] T3.1 PII 100 并发 e2e
  - Verify：对标 `pii_concurrency/stream_restore_lock`，下标无冲突；flaky 隔离标记
  - Verify：`cargo test` 全绿
- [x] T3.2 vault LRU/容量 e2e
  - Verify：LRU 逐出与 5000/1000 容量断言通过

## T4. T-M5 Matrix 与 T-M6 Go 承接（D4）

- [x] T4.1 登记承接表
  - 承接登记（D4，不闭环只追踪）：Matrix 真链路缺件说明——当前仅 `src/service/matrix/approval.rs` 内 mock 级单测（无真实 homeserver/真网 reaction 落定），真链路验证缺件（需 Matrix 房 + Bot token + 真人 reaction），owner 归 `veil-hardening` 联动，不在本 change 闭环；Go F3 5.1-5.3（存量 Go 直连全链路 / 三因子两场景 / 阻断终止）owner 为 `veil-hardening 5.x`（见 `openspec/changes/veil-hardening/tasks.md` 5.1-5.3），本 change 只登记追踪句不闭环真机联调。
  - mock 标记：`src/service/matrix/approval.rs` tests 模块（白名单/reaction 幂等 mock 单测）即现存 mock 标记，本任务零生产代码改动。
  - Verify：tasks 含 Matrix 缺件说明与 Go 5.1-5.3 owner `veil-hardening 5.x` 追踪句
  - Verify：占位 e2e 或 mock 标记存在，代码零改动

## T5. T-M7/T-M9 注明与 T-M8 薄项（D5）

- [x] T5.1 README 追加替代与口径句
  - 落点：README §8.5（`sentinel_record.py → sentinel_* e2e` 替代句 + conformance 12 vs 20 口径差异句）。
  - Verify：`grep -n "sentinel_record" README.md` 与 `grep -n "12 vs 20\|口径不同" README.md` 命中
  - Verify：`check_doc_paths` 全绿
- [x] T5.2 hook/env 最小 e2e 或书面豁免
  - 书面豁免（D5 二选一锁定选豁免）：audit hook（`AUDIT_POLICY_FILE` 缺省/文件双路径）与 env 解析细节已有单测锁定分支语义（`src/config/env_parse.rs` 14 单测 + `src/config/validate.rs`/`custom_file.rs` tests + `src/service/audit/policy.rs` tests），e2e 需真实文件挂载与进程重启矩阵、重复建设无增量信号，故豁免 e2e、以单测为准；若策略语义变更另立任务补 e2e。
  - Verify：二选一锁定，单测或豁免句存在
