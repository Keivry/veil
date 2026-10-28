//! 文件层单测：schema 严格性 / 封闭映射表 / 规范化 / 合并优先级 / 引导加载 /
//! 密钥权限门禁（对应 design D1/D3/D4/D5/D6/D7 与 tasks 2.x/3.x/4.1）。

use {
    super::*,
    crate::{
        config::{AuditMode, AutoApprove, Config, EntryMode, env_parse::test_support::base_env},
        service::audit::policy::AuditPolicy,
    },
    std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicU32, Ordering},
        },
    },
};

/// 每实例独立临时目录中的文件；`Drop` 整目录清理（并发测试互不干扰）。
struct TempFile {
    dir: PathBuf,
    path: PathBuf,
}

impl TempFile {
    fn new(name: &str, content: &str) -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "veil-file-layer-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("建临时目录");
        let path = dir.join(name);
        fs::write(&path, content).expect("写临时文件");
        Self { dir, path }
    }

    #[cfg(unix)]
    fn with_mode(name: &str, content: &str, mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let file = Self::new(name, content);
        fs::set_permissions(&file.path, fs::Permissions::from_mode(mode)).expect("chmod 临时文件");
        file
    }

    fn path(&self) -> &Path { &self.path }

    fn dir(&self) -> &Path { &self.dir }

    /// 声明密钥类键的文件：Unix 下 0600 以隔离权限门禁，非 Unix 普通写入。
    #[cfg(unix)]
    fn secret(name: &str, content: &str) -> Self { Self::with_mode(name, content, 0o600) }

    #[cfg(not(unix))]
    fn secret(name: &str, content: &str) -> Self { Self::new(name, content) }
}

impl Drop for TempFile {
    fn drop(&mut self) { fs::remove_dir_all(&self.dir).ok(); }
}

fn parse(text: &str) -> std::result::Result<FileConfig, toml::de::Error> { toml::from_str(text) }

fn apply_only(env: &mut HashMap<String, String>) {
    apply_config_file(env).expect("文件层应用须成功");
}

fn apply_and_load(env: &mut HashMap<String, String>) -> Config {
    apply_only(env);
    Config::load_from(env).expect("合并后配置须可加载")
}

fn with_config_file(file: &TempFile) -> HashMap<String, String> {
    let mut env = base_env();
    env.insert(
        BOOTSTRAP_VAR.to_string(),
        file.path().to_string_lossy().into_owned(),
    );
    env
}

fn resolved_value(cfg: &FileConfig, key: &str) -> String {
    resolve_entries(cfg)
        .expect("解析条目")
        .into_iter()
        .find(|entry| entry.key == key)
        .unwrap_or_else(|| panic!("键 {key} 须有解析产物"))
        .value
}

fn flattened_keys(cfg: &FileConfig) -> Vec<String> {
    let value = serde_json::to_value(cfg).expect("内部序列化");
    let mut leaves = Vec::new();
    collect_leaves(value, "", &mut leaves);
    let mut keys: Vec<String> = leaves
        .into_iter()
        .map(|(key, _)| {
            if key.starts_with(UPSTREAMS_KEY_PREFIX) {
                UPSTREAMS_KEY.to_string()
            } else if let Some(root) = file_only_root(&key) {
                root.to_string()
            } else {
                key
            }
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// 捕获事件 `message` 字段的订阅者（断言冲突 warn 文案）。
#[derive(Clone, Default)]
struct CaptureMessages {
    messages: Arc<Mutex<Vec<String>>>,
}

impl CaptureMessages {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.messages.lock().expect("捕获锁未中毒"))
    }
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

impl tracing::Subscriber for CaptureMessages {
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

fn capture_apply(env: &mut HashMap<String, String>) -> Vec<String> {
    let capture = CaptureMessages::default();
    let subscriber = capture.clone();
    crate::test_support::with_capture_subscriber(subscriber, || {
        apply_config_file(env).expect("文件层应用须成功");
    });
    capture.take()
}

const MAXIMAL_TOML: &str = r#"
[auth]
homeserver = "https://matrix.example.com"
room_id = "!room:example.com"
matrix_access_token = "syt-maximal-token"
observability_admin_token = "admin-token-0123456789abcdef"
observability_disable = false

[limits]
audit_hold_max_bytes = 1048576
nonstream_max_bytes = 8388608
sse_frame_hard_bytes = 8388608

[audit]
mode = "block"
timeout = 90
approval_whitelist = ["@admin:example.com", "@ops:example.com"]
policy_file = "/etc/veil/audit-policy.yaml"

[storage]
data_dir = "/srv/veil"
db_dir = "/srv/veil/db"
tpm_dir = "/srv/veil/tpm"
caller_registry_path = "/srv/veil/caller_registry.json"
veilctl_secret = "deploy-secret"
veilctl_binary_hash = "abcdef0123456789"
auto_approve = "pending"
entry_mode = "credential-only"
credential_block_wait = true
authorization_ttl_secs = 3600
request_log_enabled = true
request_log_retention_days = 7

[redaction]
enabled = true
fuzzy_restore = true
detection_hardening = true
custom_rules_file = "/etc/veil/rules.json"
custom_patterns_file = "/etc/veil/patterns.json"
custom_dict_file = "/etc/veil/dict.json"
value_sample_enabled = true
value_sample_persist = false
value_sample_hmac_key = "hmac-key"
placeholder_prompt = true
placeholder_prompt_text = "自定义说明"
normalize_json_whitespace = true

[pii_scope]
mode = "conversation"
ttl_secs = 1800
max_conversations = 2048
key_header = "x-veil-conversation-id"
prev_id_max_entries = 2048

[llm]
default_upstream = "http://127.0.0.1:11434"
timeout_secs = 30
pool_max_idle_per_host = 16
pool_idle_timeout_secs = 90

[llm.upstreams]
"8878" = "http://127.0.0.1:11434"
"8879" = "http://127.0.0.1:11435"

[keepass]
backend = "mock"
"#;

const EXPECTED_KEYS: [&str; 47] = [
    "auth.homeserver",
    "auth.room_id",
    "auth.matrix_access_token",
    "auth.observability_admin_token",
    "auth.observability_disable",
    "limits.audit_hold_max_bytes",
    "limits.nonstream_max_bytes",
    "limits.sse_frame_hard_bytes",
    "audit.mode",
    "audit.timeout",
    "audit.approval_whitelist",
    "audit.policy_file",
    "storage.data_dir",
    "storage.db_dir",
    "storage.tpm_dir",
    "storage.caller_registry_path",
    "storage.veilctl_secret",
    "storage.veilctl_binary_hash",
    "storage.auto_approve",
    "storage.entry_mode",
    "storage.credential_block_wait",
    "storage.authorization_ttl_secs",
    "storage.request_log_enabled",
    "storage.request_log_retention_days",
    "redaction.enabled",
    "redaction.fuzzy_restore",
    "redaction.detection_hardening",
    "redaction.custom_rules_file",
    "redaction.custom_patterns_file",
    "redaction.custom_dict_file",
    "redaction.value_sample_enabled",
    "redaction.value_sample_persist",
    "redaction.value_sample_hmac_key",
    "redaction.placeholder_prompt",
    "redaction.placeholder_prompt_text",
    "redaction.normalize_json_whitespace",
    "pii_scope.mode",
    "pii_scope.ttl_secs",
    "pii_scope.max_conversations",
    "pii_scope.key_header",
    "pii_scope.prev_id_max_entries",
    "llm.default_upstream",
    "llm.timeout_secs",
    "llm.pool_max_idle_per_host",
    "llm.pool_idle_timeout_secs",
    "llm.upstreams",
    "keepass.backend",
];

const ENV_PARSE_SRC: &str = include_str!("../env_parse/mod.rs");
const PII_SCOPE_SRC: &str = include_str!("../env_parse/pii_scope.rs");
const STORAGE_ENV_SRC: &str = include_str!("../env_parse/storage.rs");
const VALIDATE_SRC: &str = include_str!("../validate.rs");

#[test]
fn file_config_valid_sample_parses() {
    let cfg = parse(MAXIMAL_TOML).expect("最大样例须可解析");
    assert_eq!(
        cfg.audit.as_ref().and_then(|s| s.mode),
        Some(FileAuditMode::Block)
    );
    assert_eq!(
        cfg.storage.as_ref().and_then(|s| s.entry_mode),
        Some(FileEntryMode::CredentialOnly)
    );
    assert_eq!(
        cfg.storage.as_ref().and_then(|s| s.auto_approve),
        Some(FileAutoApprove::Pending)
    );
    assert_eq!(
        cfg.pii_scope.as_ref().and_then(|s| s.mode),
        Some(FilePiiScopeMode::Conversation)
    );
    assert_eq!(
        cfg.keepass.as_ref().and_then(|s| s.backend),
        Some(FileKeepassBackend::Mock)
    );
    assert_eq!(
        cfg.llm
            .as_ref()
            .and_then(|s| s.upstreams.as_ref())
            .map(BTreeMap::len),
        Some(2)
    );
}

#[test]
fn file_config_missing_and_empty_sections_are_legal() {
    for text in ["", "# 仅注释\n", "[audit]\n", "[audit]\n[storage]\n"] {
        assert!(parse(text).is_ok(), "缺省/空分节须合法: {text:?}");
    }
}

#[test]
fn file_config_unknown_keys_rejected() {
    for (text, key) in [
        ("[foo]\na = 1\n", "foo"),
        ("[audit]\nmode = \"off\"\nrush_log = \"info\"\n", "rush_log"),
        ("[storage]\ndata_dir = \"/x\"\nnot_a_key = 1\n", "not_a_key"),
        (
            "[auth]\nhomeserver = \"x\"\n[redaction]\nunknown_sub = true\n",
            "unknown_sub",
        ),
    ] {
        let err = parse(text).expect_err(&format!("未知键 {key} 须拒解析"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}

#[test]
fn alias_legacy_and_env_only_keys_rejected() {
    for (text, key) in [
        (
            "[redaction]\npii_redaction_enabled = true\n",
            "pii_redaction_enabled",
        ),
        ("[redaction]\npii_rules_file = \"/a\"\n", "pii_rules_file"),
        (
            "[redaction]\npii_custom_rules = \"/a\"\n",
            "pii_custom_rules",
        ),
        (
            "[redaction]\npii_custom_pattern_file = \"/a\"\n",
            "pii_custom_pattern_file",
        ),
        (
            "[redaction]\npii_custom_patterns = \"/a\"\n",
            "pii_custom_patterns",
        ),
        ("[redaction]\npii_dict_file = \"/a\"\n", "pii_dict_file"),
        (
            "[redaction]\npii_sensitive_dict_file = \"/a\"\n",
            "pii_sensitive_dict_file",
        ),
        (
            "[redaction]\npii_sensitive_names_file = \"/a\"\n",
            "pii_sensitive_names_file",
        ),
        ("[redaction]\npii_custom_dict = \"/a\"\n", "pii_custom_dict"),
        ("[audit]\naudit_enabled = true\n", "audit_enabled"),
        (
            "[auth]\ncredential_admin_token = \"x\"\n",
            "credential_admin_token",
        ),
        ("rust_log = \"info\"\n", "rust_log"),
        ("veil_allow_mock_tpm = \"1\"\n", "veil_allow_mock_tpm"),
        ("[llm]\nport_8878 = \"http://x\"\n", "port_8878"),
        ("[storage]\ntpm_host_path = \"/x\"\n", "tpm_host_path"),
        ("veil_config_file = \"/x\"\n", "veil_config_file"),
    ] {
        let err = parse(text).expect_err(&format!("键 {key} 须被拒"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
    let legacy_key: &str = concat!("get_bin", "ary_secret");
    let err = parse(&format!("[storage]\n{legacy_key} = \"x\"\n")).expect_err("遗留键名须被拒");
    assert!(
        err.to_string().contains(legacy_key),
        "错误信息须指名 {legacy_key}: {err}"
    );
}

#[test]
fn command_section_rejected_at_startup_with_key_path() {
    let file = TempFile::new(
        "bad-command.toml",
        "[command]\nenabled = true\n\n[command.commands.deploy]\nprogram = \"deploy.sh\"\n         usage = \"deploy\"\nhosts = [\"api\"]\n\n[command.hosts.api]\nkind = \"local\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("非法命令配置须拒绝启动");
    let message = err.to_string();
    assert!(
        message.contains("command.commands.deploy.program"),
        "错误须指明键路径: {message}"
    );
    assert!(message.contains("绝对路径"), "错误须说明原因: {message}");
}

#[test]
fn file_config_type_errors_rejected() {
    for (text, key) in [
        ("[audit]\ntimeout = \"30\"\n", "timeout"),
        ("[redaction]\nenabled = \"false\"\n", "enabled"),
        (
            "[auth]\nobservability_disable = \"false\"\n",
            "observability_disable",
        ),
        (
            "[storage]\ncredential_block_wait = 1\n",
            "credential_block_wait",
        ),
        (
            "[limits]\naudit_hold_max_bytes = 1.5\n",
            "audit_hold_max_bytes",
        ),
        ("[llm.upstreams]\n\"8878\" = 123\n", "8878"),
    ] {
        let err = parse(text).expect_err(&format!("类型错误 {key} 须被拒"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}

#[test]
fn file_config_enum_empty_and_invalid_rejected() {
    for text in [
        "[audit]\nmode = \"\"\n",
        "[audit]\nmode = \"x\"\n",
        "[storage]\nentry_mode = \"\"\n",
        "[storage]\nentry_mode = \"x\"\n",
        "[storage]\nauto_approve = \"\"\n",
        "[storage]\nauto_approve = \"x\"\n",
        "[pii_scope]\nmode = \"x\"\n",
        "[keepass]\nbackend = \"x\"\n",
    ] {
        assert!(
            parse(text).is_err(),
            "枚举空串/集合外取值须在 toml 解析阶段失败: {text:?}"
        );
    }
}

#[test]
fn mapping_table_locked_to_schema_and_canonical_list() {
    let cfg = parse(MAXIMAL_TOML).expect("最大样例须可解析");
    let mut expected: Vec<String> = EXPECTED_KEYS.iter().map(|key| (*key).to_string()).collect();
    expected.sort();
    assert_eq!(
        flattened_keys(&cfg),
        expected,
        "FileConfig 可声明键集须与规范清单逐项相等"
    );

    let mut mapping_keys: Vec<String> = MAPPINGS.iter().map(|m| m.key.to_string()).collect();
    mapping_keys.sort();
    assert_eq!(mapping_keys, expected, "封闭映射表键集须与规范清单逐项相等");

    let mut resolved_keys: Vec<String> = resolve_entries(&cfg)
        .expect("最大样例须可解析为条目")
        .iter()
        .map(|entry| {
            if entry.key.starts_with(UPSTREAMS_KEY_PREFIX) {
                UPSTREAMS_KEY.to_string()
            } else {
                entry.key.clone()
            }
        })
        .collect();
    resolved_keys.sort();
    resolved_keys.dedup();
    assert_eq!(resolved_keys, expected, "每条声明键须有解析产物");
}

#[test]
fn mapping_targets_are_env_read_names() {
    for mapping in MAPPINGS {
        let name = match mapping.target {
            MappingTarget::Env(name) => name,
            MappingTarget::PortTable | MappingTarget::FileOnly => continue,
        };
        let needle = format!("\"{name}\"");
        assert!(
            ENV_PARSE_SRC.contains(&needle)
                || PII_SCOPE_SRC.contains(&needle)
                || STORAGE_ENV_SRC.contains(&needle)
                || VALIDATE_SRC.contains(&needle),
            "映射目标 {name} 须为 env_parse 读取的 env 名"
        );
    }
}

#[test]
fn alias_env_explicit_name_sets_match_design() {
    fn names(key: &str) -> &'static [&'static str] {
        MAPPINGS
            .iter()
            .find(|m| m.key == key)
            .expect("映射键存在")
            .env_explicit_names
    }
    assert_eq!(
        names("redaction.enabled"),
        ["REDACTION_ENABLED", "PII_REDACTION_ENABLED"].as_slice()
    );
    assert_eq!(
        names("redaction.custom_rules_file"),
        [
            "PII_CUSTOM_RULES_FILE",
            "PII_RULES_FILE",
            "PII_CUSTOM_RULES"
        ]
        .as_slice()
    );
    assert_eq!(
        names("redaction.custom_patterns_file"),
        [
            "PII_CUSTOM_PATTERNS_FILE",
            "PII_CUSTOM_PATTERN_FILE",
            "PII_CUSTOM_PATTERNS"
        ]
        .as_slice()
    );
    assert_eq!(
        names("redaction.custom_dict_file"),
        [
            "PII_CUSTOM_DICT_FILE",
            "PII_DICT_FILE",
            "PII_SENSITIVE_DICT_FILE",
            "PII_SENSITIVE_NAMES_FILE",
            "PII_CUSTOM_DICT"
        ]
        .as_slice()
    );
    assert_eq!(
        names("storage.veilctl_secret"),
        ["VEILCTL_SECRET"].as_slice()
    );
    assert_eq!(names("audit.mode"), ["AUDIT_MODE"].as_slice());
}

#[test]
fn resolve_coerces_scalar_types() {
    let cfg = parse(
        "[redaction]\nenabled = true\nfuzzy_restore = false\n\
         [pii_scope]\nttl_secs = 1800\nkey_header = \"x-veil-conversation-id\"\n\
         [audit]\napproval_whitelist = [\"@a:example.com\", \"@b:example.com\"]\n\
         [storage]\ndata_dir = \"/srv/veil\"\n",
    )
    .expect("合法样例");
    assert_eq!(resolved_value(&cfg, "redaction.enabled"), "1");
    assert_eq!(resolved_value(&cfg, "redaction.fuzzy_restore"), "0");
    assert_eq!(resolved_value(&cfg, "pii_scope.ttl_secs"), "1800");
    assert_eq!(
        resolved_value(&cfg, "pii_scope.key_header"),
        "x-veil-conversation-id"
    );
    assert_eq!(
        resolved_value(&cfg, "audit.approval_whitelist"),
        "@a:example.com,@b:example.com"
    );
    assert_eq!(resolved_value(&cfg, "storage.data_dir"), "/srv/veil");
}

#[test]
fn resolve_coerces_enum_tokens() {
    let cfg = parse(
        "[audit]\nmode = \"approve\"\n\
         [storage]\nauto_approve = \"allow\"\nentry_mode = \"llm-only\"\n\
         [pii_scope]\nmode = \"conversation\"\n\
         [keepass]\nbackend = \"mock\"\n",
    )
    .expect("合法样例");
    assert_eq!(resolved_value(&cfg, "audit.mode"), "approve");
    assert_eq!(resolved_value(&cfg, "storage.auto_approve"), "true");
    assert_eq!(resolved_value(&cfg, "storage.entry_mode"), "llm-only");
    assert_eq!(resolved_value(&cfg, "pii_scope.mode"), "conversation");
    assert_eq!(resolved_value(&cfg, "keepass.backend"), "mock");
    for (raw, token) in [("deny", "false"), ("pending", "pending")] {
        let cfg = parse(&format!("[storage]\nauto_approve = {raw:?}\n")).expect("合法样例");
        assert_eq!(resolved_value(&cfg, "storage.auto_approve"), token);
    }
}

#[test]
fn resolve_expands_upstream_ports() {
    let cfg = parse("[llm.upstreams]\n\"8878\" = \"http://a:1\"\n8879 = \"http://b:2\"\n")
        .expect("合法样例");
    let entries = resolve_entries(&cfg).expect("解析条目");
    let mut pairs: Vec<(String, String)> = entries
        .iter()
        .map(|entry| {
            (
                entry
                    .canonical_env
                    .clone()
                    .expect("端口表条目须有规范 env 名"),
                entry.value.clone(),
            )
        })
        .collect();
    pairs.sort();
    assert_eq!(
        pairs,
        vec![
            ("LLM_8878".to_string(), "http://a:1".to_string()),
            ("LLM_8879".to_string(), "http://b:2".to_string()),
        ]
    );
    for entry in &entries {
        assert_eq!(
            entry.env_explicit_names,
            vec![
                entry
                    .canonical_env
                    .clone()
                    .expect("端口表条目须有规范 env 名")
            ]
        );
    }
}

#[test]
fn resolve_rejects_invalid_upstream_port() {
    let cfg = parse("[llm.upstreams]\n\"abc\" = \"http://a:1\"\n").expect("TOML 合法");
    let err = resolve_entries(&cfg).expect_err("端口非法须拒");
    let msg = err.to_string();
    assert!(
        msg.contains(UPSTREAMS_KEY) && msg.contains("abc"),
        "实际: {msg}"
    );
    let cfg = parse("[llm.upstreams]\n\"70000\" = \"http://a:1\"\n").expect("TOML 合法");
    assert!(resolve_entries(&cfg).is_err(), "u16 溢出端口须拒");
}

#[test]
fn bootstrap_absent_or_blank_does_not_touch_files() {
    let baseline = base_env();
    for raw in ["", "   ", "\t"] {
        let mut env = baseline.clone();
        env.insert(BOOTSTRAP_VAR.to_string(), raw.to_string());
        apply_only(&mut env);
        env.remove(BOOTSTRAP_VAR);
        assert_eq!(env, baseline, "空白引导变量须零副作用");
    }
}

#[test]
fn bootstrap_missing_or_directory_rejects() {
    let mut env = base_env();
    env.insert(
        BOOTSTRAP_VAR.to_string(),
        "/nonexistent/veil-dir/veil.toml".to_string(),
    );
    let err = apply_config_file(&mut env).unwrap_err();
    assert!(
        err.to_string().contains(BOOTSTRAP_VAR),
        "缺失文件须指名引导变量: {err}"
    );

    let dir = TempFile::new("dir-target.toml", "# 占位\n");
    let mut env = base_env();
    env.insert(
        BOOTSTRAP_VAR.to_string(),
        dir.dir().to_string_lossy().into_owned(),
    );
    let err = apply_config_file(&mut env).unwrap_err();
    assert!(
        err.to_string().contains(BOOTSTRAP_VAR),
        "目录路径须拒启动: {err}"
    );
}

#[test]
fn bootstrap_oversize_rejects_and_exact_limit_allows() {
    let over = TempFile::new(
        "oversize.toml",
        &"#".repeat(CUSTOM_FILE_MAX_BYTES as usize + 1),
    );
    let mut env = with_config_file(&over);
    let err = apply_config_file(&mut env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(BOOTSTRAP_VAR) && msg.contains("1MB"),
        "实际: {msg}"
    );

    let exact = TempFile::new("at-limit.toml", &"#".repeat(CUSTOM_FILE_MAX_BYTES as usize));
    let mut env = with_config_file(&exact);
    apply_only(&mut env);
}

#[test]
fn bootstrap_syntax_error_and_unknown_key_reject() {
    let syntax = TempFile::new("syntax.toml", "[audit]\nmode = \"off\"\nbroken =\n");
    let mut env = with_config_file(&syntax);
    let err = apply_config_file(&mut env).unwrap_err();
    assert!(
        err.to_string().contains(BOOTSTRAP_VAR),
        "语法错误须指名 {BOOTSTRAP_VAR}: {err}"
    );

    let unknown = TempFile::new(
        "unknown.toml",
        "[audit]\nmode = \"off\"\nrush_log = \"x\"\n",
    );
    let mut env = with_config_file(&unknown);
    let err = apply_config_file(&mut env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(BOOTSTRAP_VAR) && msg.contains("rush_log"),
        "未知键须指名: {msg}"
    );
}

#[test]
fn bootstrap_empty_file_is_legal() {
    for content in ["", "   \n\t\n"] {
        let file = TempFile::new("empty.toml", content);
        let mut env = with_config_file(&file);
        let cfg = apply_and_load(&mut env);
        assert_eq!(
            cfg,
            Config::load_from(&base_env()).unwrap(),
            "空文件等价无覆盖"
        );
    }
}

#[test]
fn merge_env_canonical_wins_over_file_and_warns() {
    let file = TempFile::new(
        "canonical-wins.toml",
        "[audit]\nmode = \"block\"\n[pii_scope]\nttl_secs = 99\n",
    );
    let mut env = with_config_file(&file);
    env.insert("AUDIT_MODE".to_string(), "off".to_string());
    env.insert("PII_SCOPE_TTL_SECS".to_string(), "3600".to_string());
    let messages = capture_apply(&mut env);
    assert_eq!(env.get("AUDIT_MODE").map(String::as_str), Some("off"));
    assert_eq!(
        env.get("PII_SCOPE_TTL_SECS").map(String::as_str),
        Some("3600")
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("audit.mode") && m.contains("AUDIT_MODE")),
        "冲突须记指名概念的 warn: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("pii_scope.ttl_secs")),
        "冲突须记指名概念的 warn: {messages:?}"
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.audit_mode, AuditMode::Off);
    assert_eq!(cfg.pii_scope_ttl_secs, 3600);
}

#[test]
fn merge_blank_env_falls_back_to_file() {
    let file = TempFile::new(
        "blank-env.toml",
        "[pii_scope]\nttl_secs = 99\n[redaction]\nenabled = false\n",
    );
    let mut env = with_config_file(&file);
    env.insert("PII_SCOPE_TTL_SECS".to_string(), "   ".to_string());
    env.insert("REDACTION_ENABLED".to_string(), "\t".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.pii_scope_ttl_secs, 99);
    assert!(!cfg.redaction_enabled);
    assert_eq!(
        env.get("PII_SCOPE_TTL_SECS").map(String::as_str),
        Some("99"),
        "空白 env 视同未设置，文件值写入"
    );
}

#[test]
fn merge_env_aliases_win_over_file_canonical_keys() {
    let file = TempFile::new("alias-enabled.toml", "[redaction]\nenabled = true\n");
    let mut env = with_config_file(&file);
    env.insert("PII_REDACTION_ENABLED".to_string(), "0".to_string());
    let cfg = apply_and_load(&mut env);
    assert!(!cfg.redaction_enabled, "env 别名关闭须恒胜文件开启");
    assert!(
        !env.contains_key("REDACTION_ENABLED"),
        "冲突时不得写入规范名"
    );

    let rules = TempFile::new(
        "alias-rules.json",
        r#"[{"name":"ext-id","pattern":"EXT-\\d{6}"}]"#,
    );
    let file = TempFile::new(
        "alias-rules.toml",
        "[redaction]\ncustom_rules_file = \"/nonexistent/file-would-win.json\"\n",
    );
    let mut env = with_config_file(&file);
    env.insert(
        "PII_RULES_FILE".to_string(),
        rules.path().to_string_lossy().into_owned(),
    );
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.path()));
    assert!(!env.contains_key("PII_CUSTOM_RULES_FILE"));

    let file = TempFile::secret(
        "alias-secret.toml",
        "[storage]\nveilctl_secret = \"file-secret\"\n",
    );
    let mut env = with_config_file(&file);
    env.insert(
        concat!("CREDENTIAL", "_SECRET").to_string(),
        "env-alias-secret".to_string(),
    );
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.veilctl_secret.as_deref(), Some("file-secret"));
    assert!(env.contains_key("VEILCTL_SECRET"));
}

#[test]
fn merge_ignores_legacy_audit_enabled_file_mode_wins() {
    for raw in ["true", " ON ", "1", "yes"] {
        let file = TempFile::new("audit-enabled.toml", "[audit]\nmode = \"off\"\n");
        let mut env = with_config_file(&file);
        env.insert("AUDIT_ENABLED".to_string(), raw.to_string());
        let messages = capture_apply(&mut env);
        assert_eq!(
            env.get("AUDIT_MODE").map(String::as_str),
            Some("off"),
            "AUDIT_ENABLED 不再是 env 显式，文件 mode 须写入"
        );
        assert!(
            !messages.iter().any(|m| m.contains("AUDIT_ENABLED")),
            "AUDIT_ENABLED 不应再触发审计冲突 warn: {messages:?}"
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.audit_mode,
            AuditMode::Off,
            "AUDIT_ENABLED 真值 {raw:?} 不得再回退 block"
        );
        assert!(cfg.audit_mode_explicit, "文件写入 AUDIT_MODE 后视同显式");
    }
}

#[test]
fn audit_file_mode_wins_policy_file_mode() {
    let policy_off = TempFile::new("policy-off.yaml", "mode: off\n");
    let policy_block = TempFile::new("policy-block.yaml", "mode: block\n");
    let config_file = TempFile::new("audit-file-block.toml", "[audit]\nmode = \"block\"\n");

    let mut env = with_config_file(&config_file);
    let mut cfg = apply_and_load(&mut env);
    assert!(cfg.audit_mode_explicit, "文件 mode 视同显式");
    let policy = AuditPolicy::load_from_file(Some(policy_off.path())).expect("策略文件可解析");
    policy.apply_effective_mode(&mut cfg);
    assert_eq!(
        cfg.audit_mode,
        AuditMode::Block,
        "配置文件 mode 须优先于策略文件 mode"
    );

    let mut env = with_config_file(&config_file);
    env.insert("AUDIT_MODE".to_string(), "off".to_string());
    let mut cfg = apply_and_load(&mut env);
    let policy = AuditPolicy::load_from_file(Some(policy_block.path())).expect("策略文件可解析");
    policy.apply_effective_mode(&mut cfg);
    assert_eq!(cfg.audit_mode, AuditMode::Off, "env 显式须恒胜");
}

#[test]
fn legacy_audit_enabled_ignored_policy_mode_applies() {
    let policy_off = TempFile::new("policy-off-2.yaml", "mode: off\n");
    let config_file = TempFile::new("audit-enabled-policy.toml", "[audit]\nmode = \"off\"\n");
    let mut env = with_config_file(&config_file);
    env.insert("AUDIT_ENABLED".to_string(), "true".to_string());
    let mut cfg = apply_and_load(&mut env);
    let policy = AuditPolicy::load_from_file(Some(policy_off.path())).expect("策略文件可解析");
    policy.apply_effective_mode(&mut cfg);
    assert_eq!(
        cfg.audit_mode,
        AuditMode::Off,
        "AUDIT_ENABLED 已废弃，须以文件 mode 为准"
    );
}

#[test]
fn llm_upstream_ports_merge_by_port() {
    let file = TempFile::new(
        "llm-ports.toml",
        "[llm.upstreams]\n\"8879\" = \"http://file-8879:1\"\n\"8890\" = \"http://file-8890:1\"\n",
    );
    let mut env = with_config_file(&file);
    env.insert("LLM_8878".to_string(), "http://env-8878:1".to_string());
    env.insert("LLM_8890".to_string(), "http://env-8890:1".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(
        cfg.llm_upstreams.get(&8878).map(String::as_str),
        Some("http://env-8878:1")
    );
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://file-8879:1")
    );
    assert_eq!(
        cfg.llm_upstreams.get(&8890).map(String::as_str),
        Some("http://env-8890:1"),
        "同端口 env 恒胜"
    );
    assert_eq!(cfg.llm_upstreams.len(), 3);

    let file_only = TempFile::new(
        "llm-file-only.toml",
        "[llm.upstreams]\n8879 = \"http://file:1\"\n",
    );
    let mut env = with_config_file(&file_only);
    let cfg = apply_and_load(&mut env);
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://file:1")
    );

    let empty = TempFile::new("llm-empty.toml", "");
    let mut env = with_config_file(&empty);
    env.insert("LLM_8879".to_string(), "http://env:1".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://env:1")
    );
    assert_eq!(cfg.llm_upstreams.len(), 1);

    let none = TempFile::new("llm-none.toml", "");
    let mut env = with_config_file(&none);
    let cfg = apply_and_load(&mut env);
    assert!(cfg.llm_upstreams.is_empty(), "两处皆缺不得新增端口");
}

#[test]
fn llm_invalid_port_via_file_rejects_startup() {
    let file = TempFile::new(
        "llm-bad-port.toml",
        "[llm.upstreams]\n\"abc\" = \"http://x:1\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(BOOTSTRAP_VAR) && msg.contains("abc"),
        "实际: {msg}"
    );
}

#[test]
fn file_without_targets_stays_env_only_baseline() {
    // task 5.2：文件含默认值键（非 targets）时零变化——返回空覆盖表、cfg 与
    // env-only 基线逐字段相等，且不新增与 [llm.targets] 相关的告警。
    let file = TempFile::new(
        "no-targets.toml",
        "[limits]\naudit_hold_max_bytes = 1048576\n[llm]\ntimeout_secs = 30\n",
    );
    let mut env = with_config_file(&file);
    let capture = CaptureMessages::default();
    let outcome = crate::test_support::with_capture_subscriber(capture.clone(), || {
        apply_config_file(&mut env).expect("文件层应用须成功")
    });
    let messages = capture.take();
    assert!(outcome.llm_targets.is_empty(), "未声明覆盖须返回空表");
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("llm.targets")),
        "未声明 [llm.targets] 不得新增相关告警: {messages:?}"
    );
    let cfg =
        Config::load_from_with_targets(&env, outcome.llm_targets).expect("合并后配置须可加载");
    assert_eq!(
        cfg,
        Config::load_from(&base_env()).unwrap(),
        "设文件但未声明 [llm.targets] 须与 env-only 基线逐字段相等"
    );
}

#[test]
fn file_data_dir_derives_db_tpm_and_registry_paths() {
    let file = TempFile::new(
        "data-dir.toml",
        "[storage]\ndata_dir = \"/srv/veil-data\"\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.data_dir, PathBuf::from("/srv/veil-data"));
    assert_eq!(cfg.db_dir, PathBuf::from("/srv/veil-data/db"));
    assert_eq!(cfg.tpm_dir, PathBuf::from("/srv/veil-data/tpm"));
    assert_eq!(
        cfg.registry_path,
        PathBuf::from("/srv/veil-data/caller_registry.json")
    );
}

#[test]
fn file_max_conversations_defaults_prev_id_entries() {
    let file = TempFile::new("max-conv.toml", "[pii_scope]\nmax_conversations = 2000\n");
    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.pii_scope_max_conversations, 2000);
    assert_eq!(
        cfg.pii_prev_id_max_entries, 2000,
        "prev_id 默认须联动生效值"
    );
}

#[test]
fn integration_absent_file_layer_is_baseline() {
    let mut env = base_env();
    apply_only(&mut env);
    assert_eq!(env, base_env());
    assert_eq!(
        Config::load_from(&env).unwrap(),
        Config::load_from(&base_env()).unwrap(),
        "未设引导变量须与基线逐字段相等"
    );
}

#[test]
fn integration_file_only_and_env_precedence() {
    let file = TempFile::new(
        "integration.toml",
        "[storage]\nentry_mode = \"llm-only\"\nauto_approve = \"deny\"\n\
         [redaction]\nfuzzy_restore = true\nenabled = false\n\
         [llm]\ndefault_upstream = \"http://file-upstream:11434\"\ntimeout_secs = 12\n",
    );

    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.entry_mode, EntryMode::LlmOnly);
    assert_eq!(cfg.auto_approve, AutoApprove::Deny);
    assert!(cfg.pii_fuzzy_restore);
    assert!(!cfg.redaction_enabled);
    assert_eq!(
        cfg.llm_default_upstream.as_deref(),
        Some("http://file-upstream:11434")
    );
    assert_eq!(cfg.http_timeout_secs, 12);

    let mut env = with_config_file(&file);
    env.insert("VEIL_ENTRY_MODE".to_string(), "full".to_string());
    env.insert("AUTO_APPROVE".to_string(), "pending".to_string());
    env.insert("HTTP_TIMEOUT_SECS".to_string(), "45".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.entry_mode, EntryMode::Full);
    assert_eq!(cfg.auto_approve, AutoApprove::Pending);
    assert_eq!(cfg.http_timeout_secs, 45);
    assert!(cfg.pii_fuzzy_restore, "未冲突键仍取文件值");
}

#[cfg(unix)]
#[test]
fn secret_keys_with_wide_permissions_rejected() {
    let cases = [
        (
            "[auth]\nmatrix_access_token = \"syt-token\"\n",
            "matrix_access_token",
        ),
        (
            "[auth]\nobservability_admin_token = \"0123456789abcdef0123456789abcdef\"\n",
            "observability_admin_token",
        ),
        (
            "[storage]\nveilctl_secret = \"deploy-secret\"\n",
            "veilctl_secret",
        ),
        (
            "[storage]\nveilctl_binary_hash = \"abcdef0123456789\"\n",
            "veilctl_binary_hash",
        ),
        (
            "[redaction]\nvalue_sample_hmac_key = \"hmac-key\"\n",
            "value_sample_hmac_key",
        ),
    ];
    for (index, (content, key)) in cases.iter().enumerate() {
        let file = TempFile::with_mode(&format!("secret-wide-{index}.toml"), content, 0o644);
        let mut env = with_config_file(&file);
        let err = apply_config_file(&mut env).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("chmod 600") && msg.contains("644"),
            "密钥键 {key} 宽权限须拒启动并给指引: {msg}"
        );
    }
}

#[cfg(unix)]
#[test]
fn secret_key_with_narrow_permissions_passes() {
    let file = TempFile::with_mode(
        "secret-narrow.toml",
        "[storage]\nveilctl_secret = \"deploy-secret\"\n",
        0o600,
    );
    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.veilctl_secret.as_deref(), Some("deploy-secret"));
    assert_eq!(
        env.get("VEILCTL_SECRET").map(String::as_str),
        Some("deploy-secret")
    );
}

#[cfg(unix)]
#[test]
fn non_secret_wide_permissions_pass() {
    let file = TempFile::with_mode("non-secret.toml", "[redaction]\nenabled = false\n", 0o644);
    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert!(!cfg.redaction_enabled, "无密钥不得施加权限门禁");
}

#[cfg(unix)]
#[test]
fn secret_env_override_does_not_exempt_gate() {
    let file = TempFile::with_mode(
        "secret-env-override.toml",
        "[storage]\nveilctl_secret = \"file-secret\"\n",
        0o644,
    );
    let mut env = with_config_file(&file);
    env.insert("VEILCTL_SECRET".to_string(), "env-secret".to_string());
    let err = apply_config_file(&mut env).unwrap_err();
    assert!(
        err.to_string().contains("chmod 600"),
        "env 覆盖不豁免门禁（密钥已落盘）: {err}"
    );
}

#[test]
fn file_value_bounds_reuse_env_validation() {
    for (content, var) in [
        ("[audit]\ntimeout = 120\n", "AUDIT_TIMEOUT"),
        (
            "[limits]\naudit_hold_max_bytes = 0\n",
            "AUDIT_HOLD_MAX_BYTES",
        ),
        ("[limits]\nnonstream_max_bytes = 0\n", "NONSTREAM_MAX_BYTES"),
        ("[llm]\ntimeout_secs = 0\n", "HTTP_TIMEOUT_SECS"),
    ] {
        let file = TempFile::new("bounds.toml", content);
        let mut env = with_config_file(&file);
        apply_only(&mut env);
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains(var),
            "文件值越界须沿用既有 env 校验并指名 {var}: {err}"
        );
    }

    let file = TempFile::new("approve-empty.toml", "[audit]\nmode = \"approve\"\n");
    let mut env = with_config_file(&file);
    apply_only(&mut env);
    let err = Config::load_from(&env).unwrap_err();
    assert!(
        err.to_string().contains("APPROVAL_WHITELIST"),
        "approve 空白名单门禁须沿用: {err}"
    );
}

mod docs_lockstep;
mod env_read_surface;
mod redline;
mod server_bind;
mod storage;
