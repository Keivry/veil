//! `env_surface` 单测：清单锁定、`LLM_<port>` 解析一致性、过滤边界、置位告警。

use {
    super::*,
    std::sync::{Arc, Mutex},
};

/// 记录事件 `message` 字段的订阅者（仅记录，不落输出通道）。
#[derive(Clone, Default)]
struct Recorder {
    messages: Arc<Mutex<Vec<String>>>,
}

struct MessageVisitor<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        }
    }
}

impl tracing::Subscriber for Recorder {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut messages = self.messages.lock().expect("捕获锁未中毒");
        event.record(&mut MessageVisitor(&mut messages));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// 线程局部捕获执行 `f` 期间记录的全部事件 `message`（经共享探针，避免
/// `Interest::never` 全局缓存；见 `crate::test_support`）。
fn capture_events(f: impl FnOnce()) -> Vec<String> {
    let recorder = Recorder::default();
    let handle = recorder.clone();
    crate::test_support::with_capture_subscriber(recorder, f);
    handle.messages.lock().expect("捕获锁未中毒").clone()
}

/// 收敛后 `HOMESERVER`/`ROOM_ID` 属迁移概念，会先被 `filter_process_env` 剔除；
/// `from_env_map` 用例须经配置文件补足认证两键。返回（文件路径，待清理目录）。
fn auth_config_file(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "veil-env-surface-auth-{}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("veil.toml");
    std::fs::write(
        &path,
        "[auth]\nhomeserver = \"https://matrix.example.com\"\nroom_id = \"!room:example.com\"\n",
    )
    .expect("写临时认证文件");
    (path, dir)
}

#[test]
fn whitelist_and_migrated_counts_locked() {
    assert_eq!(CONFIG_ENV_WHITELIST.len(), 9, "白名单须恰 9 个具名项");
    assert_eq!(MIGRATED_ENV_VARS.len(), 47, "迁移清单须恰 47 项");

    let whitelist: std::collections::BTreeSet<&str> =
        CONFIG_ENV_WHITELIST.iter().copied().collect();
    assert_eq!(whitelist.len(), 9, "白名单不得有重复项");
    let migrated: std::collections::BTreeSet<&str> = MIGRATED_ENV_VARS.iter().copied().collect();
    assert_eq!(migrated.len(), 47, "迁移清单不得有重复项");
    assert!(
        whitelist.is_disjoint(&migrated),
        "白名单与迁移清单不得相交（同一名不得两处并存）"
    );

    // 具名项抽查（完整集合锁步由 tasks 3.2 的机检承接）。
    for name in [
        "VEIL_CONFIG_FILE",
        "RUST_LOG",
        "HOME",
        "VEIL_ALLOW_MOCK_TPM",
        "PII_VALUE_SAMPLE_HMAC_KEY",
    ] {
        assert!(whitelist.contains(name), "白名单缺 {name}");
    }
    for name in [
        "AUDIT_MODE",
        "DB_DIR",
        "REDACTION_ENABLED",
        "SSE_FRAME_HARD_BYTES",
        "HOMESERVER",
        "ROOM_ID",
        "DATA_DIR",
        "LLM_UPSTREAM",
    ] {
        assert!(migrated.contains(name), "迁移清单缺 {name}");
    }
    for name in ["HOMESERVER", "ROOM_ID", "DATA_DIR", "LLM_UPSTREAM"] {
        assert!(
            !whitelist.contains(name),
            "收敛后 {name} 不得再属白名单（已归迁移概念）"
        );
    }
}

#[test]
fn parse_llm_port_single_semantics() {
    assert_eq!(parse_llm_port("LLM_8878"), Some(8878));
    assert_eq!(parse_llm_port("LLM_+8878"), Some(8878), "前导 + 须可解析");
    assert_eq!(parse_llm_port("LLM_0"), Some(0));
    assert_eq!(parse_llm_port("LLM_65535"), Some(65535));
    assert_eq!(parse_llm_port("LLM_65536"), None, "越界端口须拒绝");
    assert_eq!(parse_llm_port("LLM_abc"), None, "不可 parse 须拒绝");
    assert_eq!(parse_llm_port("LLM_"), None);
    assert_eq!(parse_llm_port("LLM8878"), None);
    assert_eq!(parse_llm_port("XLLM_8878"), None);

    // 与 `load_llm` 同语义：`LLM_+8878` 在装载链上同样写入 8878。
    let mut env = crate::config::env_parse::test_support::base_env();
    env.insert(
        "LLM_+8878".to_string(),
        "http://127.0.0.1:18081".to_string(),
    );
    let cfg = crate::config::Config::load_from(&env).unwrap();
    assert_eq!(
        cfg.llm_upstreams.get(&8878).map(String::as_str),
        Some("http://127.0.0.1:18081"),
        "`load_llm` 须与 parse_llm_port 同结论"
    );
}

#[test]
fn filter_keeps_only_whitelist_drops_rest() {
    let map = HashMap::from([
        ("VEIL_CONFIG_FILE".to_string(), "/tmp/veil.toml".to_string()),
        ("DATA_DIR".to_string(), "/tmp/veil-data".to_string()),
        ("LLM_8878".to_string(), "http://127.0.0.1:18080".to_string()),
        ("REDACTION_ENABLED".to_string(), "0".to_string()),
        ("DB_DIR".to_string(), "/tmp/veil-db".to_string()),
        ("AUDIT_MODE".to_string(), "block".to_string()),
        ("LLM_abc".to_string(), "http://127.0.0.1:1".to_string()),
    ]);
    let filtered = filter_process_env(map);
    assert!(filtered.contains_key("VEIL_CONFIG_FILE"), "引导名须保留");
    assert!(
        !filtered.contains_key("DATA_DIR"),
        "DATA_DIR 属迁移概念，须剔除"
    );
    assert!(
        !filtered.contains_key("LLM_8878"),
        "`LLM_<port>` 模式已不保留，须剔除"
    );
    assert!(!filtered.contains_key("REDACTION_ENABLED"), "迁移名须剔除");
    assert!(!filtered.contains_key("DB_DIR"), "迁移名须剔除");
    assert!(!filtered.contains_key("AUDIT_MODE"), "迁移名须剔除");
    assert!(
        !filtered.contains_key("LLM_abc"),
        "不可 parse 的 LLM_ 键须剔除"
    );
    assert_eq!(filtered.len(), 1, "仅白名单名存活");
}

#[test]
fn migrated_set_warns_before_drop_and_blank_silent() {
    let map = HashMap::from([
        ("AUDIT_MODE".to_string(), "block".to_string()),
        ("DB_DIR".to_string(), "/tmp/veil-db".to_string()),
        ("REDACTION_ENABLED".to_string(), "   ".to_string()),
    ]);
    let messages = capture_events(|| warn_migrated_and_legacy(&map));
    assert!(
        messages
            .iter()
            .any(|m| m.contains("AUDIT_MODE") && m.contains("VEIL_CONFIG_FILE")),
        "迁移名置位须指名并指引 VEIL_CONFIG_FILE: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("DB_DIR") && m.contains("VEIL_CONFIG_FILE")),
        "迁移名置位须指名并指引 VEIL_CONFIG_FILE: {messages:?}"
    );
    assert!(
        !messages.iter().any(|m| m.contains("REDACTION_ENABLED")),
        "空白值不得告警: {messages:?}"
    );
    // warn-before-drop：告警发生在过滤前，过滤后迁移名确实不在 map。
    assert!(!filter_process_env(map).contains_key("AUDIT_MODE"));
}

/// `LLM_<port>` 模式置位告警（现状化文案）：仅可解析端口告警，不可解析/越界静默。
#[test]
fn llm_port_pattern_warns_before_drop_and_invalid_silent() {
    let map = HashMap::from([
        ("LLM_8878".to_string(), "http://127.0.0.1:18080".to_string()),
        (
            "LLM_+8878".to_string(),
            "http://127.0.0.1:18081".to_string(),
        ),
        ("LLM_FOO".to_string(), "http://127.0.0.1:18082".to_string()),
        (
            "LLM_65536".to_string(),
            "http://127.0.0.1:18083".to_string(),
        ),
        ("LLM_".to_string(), "http://127.0.0.1:18084".to_string()),
    ]);
    let messages = capture_events(|| warn_migrated_and_legacy(&map));
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("LLM_8878 ") && m.contains("VEIL_CONFIG_FILE")),
        "可解析端口须指名并指引 VEIL_CONFIG_FILE: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("LLM_+8878 ") && m.contains("VEIL_CONFIG_FILE")),
        "前导 + 可解析端口须同样告警: {messages:?}"
    );
    for silent in ["LLM_FOO", "LLM_65536", "LLM_"] {
        assert!(
            !messages
                .iter()
                .any(|m| m.starts_with(&format!("{silent} "))),
            "不可解析/越界 {silent} 不得告警: {messages:?}"
        );
    }
}

#[test]
fn legacy_set_warns_with_description() {
    let map = HashMap::from([
        ("CREDENTIAL_PORT".to_string(), "9999".to_string()),
        ("AUDIT_ENABLED".to_string(), "true".to_string()),
        ("CREDENTIAL_ADMIN_TOKEN".to_string(), "token".to_string()),
    ]);
    let messages = capture_events(|| warn_migrated_and_legacy(&map));
    assert!(
        messages
            .iter()
            .any(|m| m.contains("CREDENTIAL_PORT") && m.contains("PORT_8877")),
        "遗留名置位须附带中文说明: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("AUDIT_ENABLED") && m.contains("[audit].mode")),
        "AUDIT_ENABLED 须指引改用 [audit].mode: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("CREDENTIAL_ADMIN_TOKEN") && m.contains("交叉校验")),
        "CREDENTIAL_ADMIN_TOKEN 须附废除说明: {messages:?}"
    );
}

/// 告警函数签名返回 `()`，结构上不存在 `Err` 路径；空 map 亦不 panic。
#[test]
fn warn_function_never_errors() {
    warn_migrated_and_legacy(&HashMap::new());
    let map = HashMap::from([("AUDIT_MODE".to_string(), "bogus".to_string())]);
    warn_migrated_and_legacy(&map);
}

/// tasks 3.2③：白名单 ↔ `filter_process_env` 保留集合（恰为白名单，无 `LLM_<port>`）。
#[test]
fn filter_retains_exactly_whitelist() {
    let mut map = HashMap::new();
    for name in CONFIG_ENV_WHITELIST {
        map.insert(name.to_string(), "v".to_string());
    }
    map.insert("LLM_8878".to_string(), "http://127.0.0.1:18080".to_string());
    map.insert("LLM_8879".to_string(), "http://127.0.0.1:18081".to_string());
    map.insert("AUDIT_MODE".to_string(), "block".to_string());
    map.insert("TOTALLY_UNKNOWN".to_string(), "x".to_string());
    map.insert("LLM_abc".to_string(), "x".to_string());

    let filtered = filter_process_env(map);
    let kept: std::collections::BTreeSet<String> = filtered.keys().cloned().collect();
    let want: std::collections::BTreeSet<String> =
        CONFIG_ENV_WHITELIST.iter().map(|s| s.to_string()).collect();
    assert_eq!(kept, want, "过滤保留集合须恰为白名单");
}

/// 纯缝 `from_env_map`：迁移键在装载前被过滤，未声明时取内建默认。
#[test]
fn from_env_map_filters_migrated_then_builtin_default() {
    let (auth, dir) = auth_config_file("migrated-default");
    let mut map = crate::config::env_parse::test_support::base_env();
    map.insert(
        "VEIL_CONFIG_FILE".to_string(),
        auth.to_string_lossy().into_owned(),
    );
    map.insert("REDACTION_ENABLED".to_string(), "0".to_string());
    map.insert("AUDIT_TIMEOUT".to_string(), "120".to_string());
    let cfg = crate::config::Config::from_env_map(map).expect("迁移键不得拒启动（早已被过滤）");
    assert!(cfg.redaction_enabled, "迁移键 REDACTION_ENABLED 不得再生效");
    assert_eq!(
        cfg.audit_timeout_secs, 90,
        "迁移键 AUDIT_TIMEOUT 不得再生效"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// 纯缝 `from_env_map`：白名单键仍生效；`DATA_DIR`/`LLM_UPSTREAM` 归迁移概念后 env 置位失效。
#[test]
fn from_env_map_keeps_whitelist_keys_effective_and_migrates_deploy_keys() {
    let (auth, dir) = auth_config_file("whitelist-effective");
    let mut map = crate::config::env_parse::test_support::base_env();
    map.insert(
        "VEIL_CONFIG_FILE".to_string(),
        auth.to_string_lossy().into_owned(),
    );
    map.insert("DATA_DIR".to_string(), "/srv/veil".to_string());
    map.insert("VEILCTL_SECRET".to_string(), "deploy-secret".to_string());
    map.insert(
        "LLM_UPSTREAM".to_string(),
        "http://127.0.0.1:11434".to_string(),
    );
    let cfg = crate::config::Config::from_env_map(map).unwrap();
    assert_eq!(
        cfg.data_dir,
        std::path::PathBuf::from("/data"),
        "DATA_DIR 属迁移概念，env 置位不得生效（取内建默认）"
    );
    assert_eq!(
        cfg.veilctl_secret.as_deref(),
        Some("deploy-secret"),
        "白名单密钥键仍生效"
    );
    assert_eq!(
        cfg.llm_default_upstream, None,
        "LLM_UPSTREAM 属迁移概念，env 置位不得生效"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// 纯缝 `from_env_map`：过滤先于 `apply_config_file`，文件值在过滤后仍生效
/// （若迁移名未被过滤，`merge_entries` 会误判 env 显式从而压过文件值）。
#[test]
fn from_env_map_applies_config_file_after_filter() {
    let dir = std::env::temp_dir().join(format!(
        "veil-env-surface-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("veil.toml");
    std::fs::write(
        &path,
        "[auth]\nhomeserver = \"https://matrix.example.com\"\nroom_id = \"!room:example.com\"\n\n\
         [redaction]\nenabled = false\n",
    )
    .expect("写临时文件");
    let mut map = crate::config::env_parse::test_support::base_env();
    map.insert(
        "VEIL_CONFIG_FILE".to_string(),
        path.to_string_lossy().into_owned(),
    );
    map.insert("REDACTION_ENABLED".to_string(), "1".to_string());
    let cfg = crate::config::Config::from_env_map(map).unwrap();
    assert!(
        !cfg.redaction_enabled,
        "文件值须在过滤后经 apply_config_file 生效（env 迁移名不得压过文件）"
    );
    std::fs::remove_file(&path).ok();
    std::fs::remove_dir_all(&dir).ok();
}
