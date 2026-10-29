//! 遗留键面已移除的负向用例（`config-legacy-compat` 需求「配置遗留别名面在大版本移除」）。
//!
//! 0.2.0 删除了 `LEGACY_KEY_ALIASES` 与归一预扫描，旧分节与旧点键因此落进各分节既有的
//! `deny_unknown_fields`。本文件逐一锁定「每个被移除的面 → 拒绝且错误指名该键」，
//! 并留一条正向用例证明拒绝仅针对旧拼写（不是整层 fail-closed 误伤）。

use super::*;

/// 断言解析失败且错误文本指名 `needle`（只断言 `is_err` 会漏掉「拒绝理由错」）。
fn assert_rejected_naming(text: &str, needle: &str, why: &str) {
    let err = parse(text).expect_err(&format!("{why}：旧配置不得再被接受"));
    let message = err.to_string();
    assert!(
        message.contains(needle),
        "{why}：错误须指名 {needle}，实际: {message}"
    );
}

#[test]
fn legacy_section_auth_rejected_naming_section() {
    assert_rejected_naming(
        "[auth]\nhomeserver = \"https://matrix.example.com\"\n",
        "auth",
        "[auth] 分节已删除",
    );
    assert_rejected_naming(
        "[auth]\nroom_id = \"!room:example.com\"\nmatrix_access_token = \"syt_x\"\n",
        "auth",
        "[auth] 的其余旧键同样拒绝",
    );
}

#[test]
fn legacy_audit_timeout_key_rejected_naming_key() {
    assert_rejected_naming(
        "[audit]\ntimeout = 90\n",
        "timeout",
        "audit.timeout 已改名为 audit.timeout_secs",
    );
}

#[test]
fn legacy_storage_behaviour_keys_rejected() {
    assert_rejected_naming(
        "[storage]\nentry_mode = \"full\"\n",
        "entry_mode",
        "storage.entry_mode 已迁至 [server].surface_mode",
    );
    assert_rejected_naming(
        "[storage]\nauto_approve = \"allow\"\n",
        "auto_approve",
        "storage.auto_approve 已迁至 [credential].default_decision",
    );
    assert_rejected_naming(
        "[storage]\ncredential_block_wait = true\n",
        "credential_block_wait",
        "storage.credential_block_wait 已迁至 [credential.approval].block_wait",
    );
    assert_rejected_naming(
        "[storage]\nauthorization_ttl_secs = 60\n",
        "authorization_ttl_secs",
        "storage.authorization_ttl_secs 已迁至 [credential.authorization].ttl_secs",
    );
    assert_rejected_naming(
        "[storage]\nrequest_log_enabled = true\n",
        "request_log_enabled",
        "storage.request_log_enabled 已迁至 [request_log].enabled",
    );
    assert_rejected_naming(
        "[storage]\nrequest_log_retention_days = 7\n",
        "request_log_retention_days",
        "storage.request_log_retention_days 已迁至 [request_log].retention_days",
    );
}

#[test]
fn legacy_server_bind_rejected_naming_key() {
    assert_rejected_naming(
        "[server]\nbind = \"127.0.0.1:8877\"\n",
        "bind",
        "server.bind 已改名为 server.listen_addr",
    );
}

#[test]
fn legacy_command_block_wait_rejected() {
    assert_rejected_naming(
        "[command]\nenabled = false\nblock_wait = true\n",
        "block_wait",
        "command.block_wait 已迁至 [command.approval].block_wait",
    );
}

#[test]
fn legacy_target_override_key_rejected() {
    assert_rejected_naming(
        "[llm.targets.default]\noverride = false\n",
        "override",
        "目标级 override 已改名为 override_existing",
    );
    assert_rejected_naming(
        "[llm.upstreams]\n\"8878\" = \"http://127.0.0.1:11434\"\n\
         [llm.targets.\"8878\"]\noverride = true\n",
        "override",
        "端口目标下的旧键同样拒绝",
    );
}

#[test]
fn legacy_limits_keepass_sections_rejected() {
    assert_rejected_naming(
        "[limits]\naudit_hold_max_bytes = 1048576\n",
        "limits",
        "[limits] 分节已删除",
    );
    assert_rejected_naming(
        "[limits]\nsse_frame_hard_bytes = 8388608\n",
        "limits",
        "[limits] 的其余旧键同样拒绝",
    );
    assert_rejected_naming(
        "[keepass]\nbackend = \"mock\"\n",
        "keepass",
        "[keepass] 分节已删除",
    );
}

/// 反向保护：拒绝仅针对旧拼写，一份最小规范配置仍须可解析。
#[test]
fn old_keys_and_new_keys_are_not_both_accepted() {
    let modern = parse(
        "[server]\nlisten_addr = \"127.0.0.1:8877\"\nsurface_mode = \"full\"\n\
         [audit]\nmode = \"block\"\ntimeout_secs = 90\n\
         [credential]\ndefault_decision = \"pending\"\n\
         [storage]\ndata_dir = \"/srv/veil\"\n\
         [command]\nenabled = false\n[command.approval]\nblock_wait = true\n",
    );
    assert!(
        modern.is_ok(),
        "规范键配置须仍可解析（拒绝不得是整层误伤）: {:?}",
        modern.err()
    );

    let legacy = parse("[server]\nlisten_addr = \"127.0.0.1:8877\"\nbind = \"0.0.0.0:8877\"\n");
    assert!(
        legacy.is_err(),
        "新旧键并存时旧键仍须被拒（不存在优先级裁决）"
    );
}

/// 随二进制发布/供用户复制的源码零遗留名机检（把 8.2 的手工 `rg` 门槛改成可回归的断言）。
///
/// 扫描面：`src/` 生产代码（`.rs` / `.js` / `.html`，跳过 `tests.rs` 与 `tests/` 目录）、
/// `examples/**`（任意扩展名）与 `docker-compose.yml`。`.js`/`.html` 经 `include_str!`
/// 编进二进制，`examples/` 与 compose 是用户直接复制粘贴的来源——两者与 `.rs` 同属
/// 「出现在用户眼前即会被照抄」的面。负向用例必须逐字写出旧名才能喂给解析器，
/// 故测试模块不参与扫描。
#[test]
fn legacy_names_absent_from_shipped_sources() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    super::env_read_surface::collect_production_files(
        &crate_root.join("src"),
        &["rs", "js", "html"],
        &mut files,
    );
    let mut example_files = Vec::new();
    super::env_read_surface::collect_all_files(&crate_root.join("examples"), &mut example_files);
    files.append(&mut example_files);
    files.push(crate_root.join("docker-compose.yml"));
    assert!(files.len() > 50, "扫描面过小，疑路径失效: {}", files.len());

    for path in files {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("读取 {} 失败: {err}", path.display()));
        for token in LEGACY_FILE_KEY_TOKENS {
            assert!(
                !text.contains(token),
                "{} 残留遗留名 {token}（0.2.0 起一律拒收，随发布源码不得再出现）",
                path.display()
            );
        }
        for token in [
            "credential-only",
            "credential_only",
            "llm-only",
            "OBSERVABILITY_DISABLE",
            "PII_PREV_ID_MAX_ENTRIES",
        ] {
            assert!(
                !text.contains(token),
                "{} 残留遗留名 {token}（0.2.0 起一律拒收，随发布源码不得再出现）",
                path.display()
            );
        }
        let without_secs = text.replace("AUDIT_TIMEOUT_", "");
        assert!(
            !without_secs.contains("AUDIT_TIMEOUT"),
            "{} 残留遗留名 AUDIT_TIMEOUT（规范名须带 _SECS 后缀）",
            path.display()
        );
        let without_pii_prefix = text.replace("PII_NORMALIZE_JSON_WHITESPACE", "");
        assert!(
            !without_pii_prefix.contains("NORMALIZE_JSON_WHITESPACE"),
            "{} 残留遗留名 NORMALIZE_JSON_WHITESPACE（规范名带 PII_ 前缀）",
            path.display()
        );
        // `audit].timeout` 仅在紧跟 `_secs` 时合法；先剔除规范拼写再查旧拼写。
        let without_audit_secs = text.replace("audit].timeout_secs", "");
        assert!(
            !without_audit_secs.contains("audit].timeout"),
            "{} 残留遗留名 audit].timeout（规范名须带 _secs 后缀）",
            path.display()
        );
    }
}

/// 文件键旧拼写（点键与 `[section].key` 两种形态都列，命中任一即红）。
///
/// `audit].timeout` 不入本表：它有 `_secs` 合法形态，由测试内的
/// 「剔除规范拼写后再查」单独处理。
const LEGACY_FILE_KEY_TOKENS: [&str; 20] = [
    "[auth]",
    "[limits]",
    "[keepass]",
    "server.bind",
    "server].bind",
    "storage.entry_mode",
    "storage].entry_mode",
    "storage.auto_approve",
    "storage].auto_approve",
    "storage.credential_block_wait",
    "storage].credential_block_wait",
    "storage.authorization_ttl_secs",
    "storage].authorization_ttl_secs",
    "storage.request_log_enabled",
    "storage].request_log_enabled",
    "storage.request_log_retention_days",
    "storage].request_log_retention_days",
    "command].block_wait",
    "keepass.backend",
    "keepass].backend",
];
