## T1. 白名单同口径

- [x] T1.1 `NonstreamCtx` 增 `approval_whitelist: Vec<String>`；`dispatch.rs:175/227` 构造传 `state.config.approval_whitelist.clone()`
  - Verify：编译通过；相关单测全绿
- [x] T1.2 `evaluate_nonstream` 签名增 `approval_whitelist: &[String]`，内部改调 `evaluate_with_whitelist`
  - Verify：生产调用点 `nonstream.rs:170` 同步；`cargo test` 全绿
- [x] T1.3 `block_inject.rs` 测试调用点（`frames` 相关 251-310 / 461 / 475）更新签名
  - Verify：`cargo test block_inject` 全绿

## T2. 单入口收敛

- [x] T2.1 删除 `verdict.rs:66` `evaluate`；改写 `:59-65` 注释为单入口
  - Verify：`grep -rn "evaluate(" src/` 无裸调用（`evaluate_with_whitelist`/`evaluate_inner`/`evaluate_nonstream` 除外）
- [x] T2.2 更新 `verdict.rs` 自身测试（`evaluate_with_whitelist` + 测试白名单常量；降级用例显式传空）
  - Verify：`cargo test verdict` 全绿
- [x] T2.3 更新其余调用点（`block_inject.rs` 测试等）
  - Verify：`cargo test` 全绿

## T3. 错误状态边界

- [x] T3.1 `nonstream.rs` 阻断合成加 `status_u16 < 300` 守门；错误状态记审计（日志 + 指标）并透传原状态
  - Verify：400/500 场景不再返回 200 阻断体；2xx 行为不变
- [x] T3.2 错误响应内危险调用可观测（复用 `audit_blocks` 或新增计数，择一并在 design 注明）
  - Verify：指标/日志断言存在
- [x] T3.3 README §7.2 与实现同字复核（错误状态保留；2xx 阻断体）
  - Verify：grep 对照通过

## T4. 测试矩阵

- [x] T4.1 单测：approve 非空白名单 → NeedApproval pending 透传
  - Verify：新用例通过
- [x] T4.2 单测：approve 空白名单直调 → Block 降级（注释注明生产不可达）
  - Verify：新用例通过
- [x] T4.3 单测：block + 2xx → 200 阻断体
  - Verify：既有或新用例通过
- [x] T4.4 单测：block + 400 JSON 危险调用 → 状态与正文保留
  - Verify：新用例通过
- [x] T4.5 e2e：流/非流同调用 verdict 对照（`http_e2e_approval` 扩展）
  - Verify：e2e 全绿
- [x] T4.6 回归：`cargo test` + `scripts/api_conformance.py` + sentinel 回放
  - Verify：全绿
