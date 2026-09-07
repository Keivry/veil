## Why

`MockKeePass` 占位导致取用全链路止于 503，生产不可上线。原仓 `_credential._query_and_return` + `proxy.py` DB 扫描 + `_tpm` 解封构成完整语义，必须原样移植才能闭环凭据面。

## What Changes

- 接入真实 kdbx 后端（`keepass-rs`，KDBX3/4 + keyfile），替换 `MockKeePass` 为默认后端；`Mock` 仅保留单测。
- 移植 DB 选择：`DB_DIR` 扫描排序取末位 `.kdbx`，同名 `.key` 优先，多库告警，无库 503。
- 移植查询语义：`entry` 必填 400、`field` 可选（None=整条目）、`token` 默认 true；`password` 与受保护自定义属性按 `use_token` 脱敏；整条目返回 `title/username/password/url(+custom_properties)`，单字段返回 `{value}`；404/500 口径与原仓同字，自动放行路径失败发 Matrix 通知。
- 并发与密钥：`Semaphore(1)` 序列化 kdbx 访问 + `spawn_blocking` 跑阻塞解密；主密码经 TPM `startup_tpm` 派生（`TPM_DIR/seal.*`），内存零化，`mlockall` 等价尽力而为；密码变更清缓存。
- **BREAKING**：`POST /credential` 缺 `entry` 由穿透改为 400（与原仓一致，见 conformance-fix 3.3 联动）。

## Capabilities

### New Capabilities

- `keepass-real-backend`: 真实 kdbx 选择、解密、字段级查询、并发与密钥管理。

### Modified Capabilities

- 无（`credential-api` spec KeePass 条由 Non-Goal 转为实现，本 change 以新 capability 承接，不改原文件）。

## Impact

- 影响 `Cargo.toml`（新增 `keepass` + `zeroize`）、`src/keepass.rs`（Real 后端）、`src/config.rs`（`DB_DIR/TPM_DIR`）、`src/state.rs`（信号量/缓存）、`src/service/mod.rs`（查询接线）、`Dockerfile`（kdbx 运行时无新增系统依赖）。
- 不碰 `veil-conformance-fix` 进行中的终止符/env 改动（合并时以本 change 为准重放测试）。
