## 1. 后端与配置

- [x] 1.1 引入 `keepass` + `zeroize`，实现 `RealKeePass`（open/find/信号量/spawn_blocking/零化）
- [x] 1.2 `Config` 加 `DB_DIR/TPM_DIR` + `resolve_kdbx`（排序取末、同名 key 优先、多库告警）
- [x] 1.3 `CredentialBody` 加 `entry/field/token` 并接线校验（缺 entry 400）

## 2. 查询语义移植

- [x] 2.1 整条目/单字段/受保护 token 化与 404/500 口径对齐原仓
- [x] 2.2 自动放行路径失败 Matrix 通知 + 缓存失效（密码轮换清 Db）
- [x] 2.3 并发单测（冷缓存单 open）+ 临时 kdbx fixture 回放

## 3. 门禁与文档

- [x] 3.1 `VEIL_KEEPASS_BACKEND=mock` 逃生 + 生产默认 real 文档
- [x] 3.2 `cargo fmt/clippy/test` 全绿，`api_conformance` 取用链路打通到真实条目
