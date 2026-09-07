## Context

See proposal.md Why. Current `src/keepass.rs` is `MockKeePass` only; `Config` lacks `DB_DIR/TPM_DIR`; `CredentialBody` lacks `entry/field/token`; Python semantics live in `_credential._query_and_return`, `proxy.py` DB scan, `_tpm._do_unlock`.

## Goals / Non-Goals

**Goals:**

- 与原仓逐分支对齐的 kdbx 查询，可用 `keepass-rs` 离线单测覆盖。
- 阻塞解密永不占 async worker；密钥零化。

**Non-Goals:**

- kdbx 写回、条目创建/删除（只读网关）。
- 策略文件热重载、内存 `mlockall` 强保证（Linux 尽力 `mlock`，失败仅告警）。

## Decisions

- 后端选 `keepass`（sseemayer 系纯 Rust 实现，KDBX3/4 + keyfile，无系统依赖，与 pykeepass
  互通已验证）+ `zeroize` 包密钥；备选 `keepassxc-proxy` 需守护进程不采用。另有两点互操作约束：
  固件 `<String>` 元素须相邻（官方客户端默认如此；pykeepass 追加在 `<AutoType>` 之后，需建固件时前移），
  `aes` 经 Cargo.lock 收敛到 0.9 系（0.8.4 与 keepass 0.13 的 cipher 混用不可编译）。
- `RealKeePass { db_path, keyfile_path, password_provider, semaphore(1), cache: Mutex<Option<Db>> }`，`open` 经 `spawn_blocking`；`find` 谓词 `title==entry_name` 首个命中（同名多条按 username/url 排序取首，保证确定性；跳过 `Recycle Bin`），与 `find_entries(first=True)` 同义。
- DB 选择在 `Config::load_from` 后 `resolve_kdbx(DB_DIR)` 纯函数实现，排序取末、同名 key 优先，便于单测用临时目录。
- `CredentialBody` 加 `entry/field/token(Option<bool> default true)`，`service::query_keepass` 复用 `CredentialVault::register` 做 `_maybe_register`；受保护判定：`keepass-rs` `Entry` 自定义字段无保护位时，沿用原仓 fallback——非常见四字段一律走 token 化（与 `get_custom_property` 无保护位分支一致）。
- 失败通知：`query` 返 `Err(KeePassInternal)` 时调用方（auto 路径）经 `ApprovalGateway.say` 发送告警，与原仓 `_say` 对齐。

## Risks / Trade-offs

- [Risk] `keepass-rs` KDBX4 argon2 解密慢 → Mitigation：信号量 + 一次 open 缓存，超时走 500 不挂起。
- [Risk] keyfile 二进制读取失败 → Mitigation：缺失视为 None，有文件但不可读视为 500 并指明路径。
- [Risk] 与 conformance-fix 同改 `CredentialBody` 冲突 → Mitigation：本 change 以 conformance-fix 落盘为准 rebase，先合入其 `get_binary_*` 别名再加 `entry/field`。

## Migration Plan

- 按 tasks 落地，`cargo test keepass` + 临时 kdbx fixture 回放；回滚：`VEIL_KEEPASS_BACKEND=mock` 环境逃生（默认 real，显式 mock 仅 CI）。
