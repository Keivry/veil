# residual-followup Design

## Context

来源：Oracle 终审四项遗留（基线 `0a51675`，见 `openspec/changes/veil-llm-proto-closeout/design.md` 与终审日志）。约束：不放松性能门禁语义、不改网关行为、canon spec 修改须走 delta。

## Decisions

### D1（F1）：best-of-3 取最小，保持 800ms 上界

**决策**：`t8_100kb_scan_under_800ms` 连续测量 3 次取 `min` 断言 `< 800ms`；命中数断言只做一次；注释说明理由。

**理由**：单次墙钟在并行 `cargo test` 负载下受调度抖动（观测 801–833ms vs 门禁 800ms，单跑 0.30s）；三次中只要一次干净调度即可通过；真实性能回归会使三次**全部**超界，门禁强度保持。

**备选**：
- 调高阈值（放松门禁，不采用）；
- `#[ignore]` 或串行隔离（需 CI 配置，本仓无 CI workflows，不采用）；
- 改用线程 CPU 时间（无稳定标准库 API，不引入依赖）。

### D2（F2）：AtomicBool 每进程一次 warn

**决策**：`src/service/llm_gateway/mod.rs` 模块级 `static DEFAULT_FALLBACK_WARNED: AtomicBool`，仅 `swap(true, Relaxed)` 返回 false 时发 warn；消息注明后续不再重复。

**理由**：保留首次可观测（提示迁移）且消除热路径逐请求噪音；确定性单测不受影响。

### D3（F3）：delta 修改 canon 需求

**决策**：`specs/stream-protocol-parity/spec.md` 以 `## MODIFIED Requirements` 重写「Empty streams stay open-ended for chat/anthropic」：需求正文改为「open-ended 为有意语义且可观测；下游 stub 保护为外部依赖、证据见 README §8.6」；场景一改写为条件化表述；补 Anthropic 真空流场景。

**理由**：canon 与 README §8.6 同口径，消除「spec 作事实断言 vs README 待人工确认」张力；Anthropic 场景回写已实现测试。

**备选**：只改 README（canon 张力残留，不采用）。

### D4（F4）：信息项登记

非流 2xx-only 精确规则的可追溯性依赖 `veil-nonstream-audit-align` 归档合并；本 change 不动作，仅附录登记。

## Risks

- D1 若环境持续满载致三次均超界，该场景下整套测试已不可信，属环境问题而非用例问题。
- D3 归档时 MODIFIED delta 将替换 canon 原需求块；delta 已含全部两个场景（真空 + Anthropic）。

## 附录：已评估无需动作

- F4.1 非流 2xx-only 可追溯性：精确规则「仅上游 2xx 且审计命中 Block 时下游恒收 `200 + nonstream_block_body`；非 2xx 错误状态保留状态与正文、审计照记」当前仅存在于未归档 delta `veil-nonstream-audit-align`；待该 change 归档后并入 canon，本批不动作、不改 spec。
- t8 其余用例保持原样（1KB/50ms、1MB/8s、CJK/100ms、字典/20ms、增量/2s，均 ≥8x 余量）。
- Hermes 真链路证据仍为 README §8.6 open item（owner：下游集成），本 change 只对齐 spec 口径不关闭该项。

## 附录：F2.2 热路径 warn 复核

- 既有确定性单测保持通过：`upstream_port_mapping_resolves`（端口映射）与
  `resolve_upstream_default_fallback_picks_lowest_port_deterministically`（双端口取最小 + 重复 10 次一致）；
  `AtomicBool` 仅影响告警频次，端口升序选择每次确定性重算，语义未变。
- 复核结论：除本次修复的缺省回退 warn 外，`handler/llm/**` 与 `service/llm_gateway/**` 中无其它
  **无条件逐请求**热路径 warn 需处理；`pump/spawn.rs` 与 `nonstream.rs` 的「审计策略文件加载失败」
  仅在文件已配置且加载失败（错误路径）时触发，截断/回退类 warn 均为条件触发，保留其可观测性。

## 附录：F1.2 并行稳定性证据

- 连续 3 轮全量 plain `cargo test`（非 rtk 包装），退出码全 0，每轮均 738 passed / 0 failed / 19 suites：
  - 第 1 轮：738 passed，0 failed，耗时 27s
  - 第 2 轮：738 passed，0 failed，耗时 22s
  - 第 3 轮：738 passed，0 failed，耗时 20s
- best-of-3 用例 `t8_100kb_scan_under_800ms` 三轮均在默认并行度下通过，未再复现 801–833ms 调度抖动超界。
