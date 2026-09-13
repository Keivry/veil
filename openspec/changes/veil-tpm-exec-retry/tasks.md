## 1. `E1` ETXTBSY 有界重试接线

- [x] 1.1 `src/service/tpm.rs`：新增纯助手 `retry_on_exec_busy<T>(max_attempts, op)`（5 次、10–40ms 递增退避；仅 `ExecutableFileBusy`/`os error 26` 重试，其他错误立即透传）
  - 验证：`cargo test -p veil retry_on_exec_busy` 三态通过；`cargo clippy --tests --all-targets -- -D warnings` 无警告
- [x] 1.2 `RealTpm::run` 的 `spawn` 与 `is_available` 的 `Command::output()` 均改经该助手；错误文案与超时语义不变
  - 验证：`grep -n "retry_on_exec_busy" src/service/tpm.rs` 命中两处生产调用；`cargo test -p veil service::tpm` 全绿

## 2. `E2`/`E3` 单测与写入加固

- [x] 2.1 三态单测：busy×2→Ok（断言尝试 3 次）、非 busy→立即 Err（断言尝试 1 次）、busy×5→Err 且尝试恰 5 次
  - 验证：`cargo test -p veil retry_on_exec_busy` 通过；构造 `io::Error::from_raw_os_error(26)` 与 `ENOENT` 分别断言
- [x] 2.2 `write_executable` 写入后 `sync_all`（缩小写者落定窗口）+ 说明注释
  - 验证：`cargo test -p veil service::tpm` 全绿；`cargo fmt --check` 0

## 3. 稳定性验证与门禁

- [x] 3.1 TPM 组循环压测：`for i in $(seq 1 40); do cargo test -p veil service::tpm || break; done` 全绿（含 `tpm_tempdir_cleanup`）
  - 验证：40 轮均 `test result: ok`，无 `ETXTBSY`
- [x] 3.2 全量门禁：`cargo test -p veil` ×3 全绿；`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`openspec validate veil-tpm-exec-retry --strict`、`python3 scripts/check_doc_paths.py`、`python3 scripts/check_file_sizes.py` 全通过
  - 验证：三轮 `cargo test` 均 `0 failed`；validate `0 failures`；doc_paths/file_sizes exit 0
