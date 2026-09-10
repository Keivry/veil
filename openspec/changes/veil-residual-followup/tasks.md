## F1. t8 性能用例确定性（chunk.rs）

- [x] F1.1 `src/service/pii/chunk.rs` `perf_budget_tests::t8_100kb_scan_under_800ms` 连续 3 次扫描取 `min` 断言 `< 800ms`（`hits.len() > 100` 只断言一次；注释理由）
  - Verify：`cargo test --lib t8_100kb` 通过；断言含 3 次测量与 min 逻辑；800ms 上界未改
- [x] F1.2 并行负载稳定性证据：连续 3 轮全量 `cargo test` 无 flake 并登记 design 附录
  - Verify：3 轮均 738 passed（附录含结果与耗时）

## F2. resolve_upstream warn 去重

- [x] F2.1 `src/service/llm_gateway/mod.rs` `resolve_upstream` 缺省回退 warn 改模块级 `AtomicBool` 每进程一次
  - Verify：`cargo test --lib resolve_upstream` 通过；warn 由 `swap(true)` 守门
- [x] F2.2 代码复核：既有确定性单测保持（双端口取最小 + 重复一致）且无其它热路径逐请求 warn 需处理
  - Verify：单测通过；复核结论登记 design 附录

## F3. spec 口径对齐

- [x] F3.1 `specs/stream-protocol-parity/spec.md` MODIFIED delta：需求正文去 stub 保证化 + 场景一改写 + 补 Anthropic 场景
  - Verify：`openspec validate veil-residual-followup --strict` 通过
- [x] F3.2 README §8.6 与 delta 文本互引一致复核
  - Verify：两处对同一 open item（Hermes 证据待人工确认）表述一致

## F4. 信息登记

- [x] F4.1 design 附录登记非流 2xx-only 可追溯性（待 `veil-nonstream-audit-align` 归档）
  - Verify：附录条目存在（无需代码改动）

## F5. 收口门禁

- [x] F5.1 门禁：`cargo fmt --check` + `cargo clippy --all --all-targets -- -D warnings` + `cargo test` + `check_file_sizes.py` + `check_doc_paths.py` + `openspec validate --strict`
  - Verify：全部退出码 0
