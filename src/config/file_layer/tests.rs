//! 文件层单测：schema 严格性 / 封闭映射表 / 规范化 / 合并优先级 / 引导加载
//! （对应 design Decision 1 至 4 与 tasks 1.x 至 3.x）。
//!
//! 拆分：旧键拒绝用例在 `tests/legacy_removed.rs`、管理面极性在
//! `tests/admin_polarity.rs`、密钥权限门禁在 `tests/secrets.rs`、
//! `[server]` 两键在 `tests/bindings.rs`、`[storage]`/`[request_log]` 在
//! `tests/storage.rs`、审计 hold 双维度在 `tests/limits_hold.rs`、
//! 文档锁步在 `tests/docs_lockstep.rs`（行数红线保持）。

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

/// 文件层应用 + 合并装载：走生产同一条 `load_from_with_file`（`request_log` 等
/// 文件专属标量键经 `FileLayerOutcome` 进入 `Config`，不能用不带产物的
/// `Config::load_from`）。
fn apply_and_load(env: &mut HashMap<String, String>) -> Config {
    let outcome = apply_config_file(env).expect("文件层应用须成功");
    Config::load_from_with_file(env, outcome).expect("合并后配置须可加载")
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

/// 0.1.x 的 `surface_mode` 历史拼写，0.2.0 起一律拒绝（供负向用例喂入）。
pub(super) const LEGACY_SURFACE_MODES: [&str; 3] =
    ["credential-only", "credential_only", "llm-only"];

/// 声明键集展平：端口表归一为 `llm.upstreams`，其余键原样；`server.surface_mode`
/// 这类「文件专属根下的有 env 映射键」须保留精确键名（MAPPINGS 优先于根清单）。
fn flattened_keys(cfg: &FileConfig) -> Vec<String> {
    let value = serde_json::to_value(cfg).expect("内部序列化");
    let mut leaves = Vec::new();
    collect_leaves(value, "", &mut leaves);
    let mut keys: Vec<String> = leaves
        .into_iter()
        .map(|(key, _)| {
            if key.starts_with(UPSTREAMS_KEY_PREFIX) {
                UPSTREAMS_KEY.to_string()
            } else if mapping_for(&key).is_some() {
                key
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

/// 捕获事件 `message` 字段的订阅者（断言冲突/弃用 warn 文案）。
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

/// 全键样例（迁移后布局；每节至少一个键，覆盖全部 48 个映射键的文字形态）。
const MAXIMAL_TOML: &str = r#"
[server]
listen_addr = "0.0.0.0:8877"
surface_mode = "full"

[admin]
enabled = true
token = "admin-token-0123456789abcdef"

[matrix]
homeserver = "https://matrix.example.com"
room_id = "!room:example.com"
access_token = "syt-maximal-token"

[audit]
mode = "block"
timeout_secs = 90
approval_whitelist = ["@admin:example.com", "@ops:example.com"]
policy_file = "/etc/veil/audit-policy.yaml"
hold_max_bytes = 1048576
hold_max_frames = 65536

[credential]
default_decision = "pending"
vault_backend = "mock"

[credential.approval]
block_wait = true

[credential.authorization]
ttl_secs = 3600

[request_log]
enabled = true
retention_days = 7

[storage]
data_dir = "/srv/veil"
db_dir = "/srv/veil/db"
tpm_dir = "/srv/veil/tpm"
caller_registry_path = "/srv/veil/caller_registry.json"
veilctl_secret = "deploy-secret"
veilctl_binary_hash = "abcdef0123456789"

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
nonstream_max_bytes = 8388608
sse_frame_hard_bytes = 8388608

[llm.upstreams]
"8878" = "http://127.0.0.1:11434"
"8879" = "http://127.0.0.1:11435"

[llm.targets."8878".headers]
x-upstream-feature = "port-8878"

[command]
enabled = false

[command.approval]
block_wait = false
"#;

/// `FileConfig` 可声明键集（MAPPINGS 48 + 文件专属键根 3 = 51）。
const EXPECTED_KEYS: [&str; 51] = [
    "server.surface_mode",
    "server",
    "admin.enabled",
    "admin.token",
    "matrix.homeserver",
    "matrix.room_id",
    "matrix.access_token",
    "audit.mode",
    "audit.timeout_secs",
    "audit.approval_whitelist",
    "audit.policy_file",
    "audit.hold_max_bytes",
    "audit.hold_max_frames",
    "credential.default_decision",
    "credential.approval.block_wait",
    "credential.authorization.ttl_secs",
    "credential.vault_backend",
    "request_log.enabled",
    "request_log.retention_days",
    "storage.data_dir",
    "storage.db_dir",
    "storage.tpm_dir",
    "storage.caller_registry_path",
    "storage.veilctl_secret",
    "storage.veilctl_binary_hash",
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
    "llm.nonstream_max_bytes",
    "llm.sse_frame_hard_bytes",
    "llm.upstreams",
    "llm.targets",
    "command",
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
        cfg.server.as_ref().and_then(|s| s.surface_mode),
        Some(FileSurfaceMode::Full)
    );
    assert_eq!(
        cfg.credential.as_ref().and_then(|s| s.default_decision),
        Some(FileAutoApprove::Pending)
    );
    assert_eq!(
        cfg.credential.as_ref().and_then(|s| s.vault_backend),
        Some(FileKeepassBackend::Mock)
    );
    assert_eq!(
        cfg.pii_scope.as_ref().and_then(|s| s.mode),
        Some(FilePiiScopeMode::Conversation)
    );
    assert_eq!(
        cfg.llm
            .as_ref()
            .and_then(|s| s.upstreams.as_ref())
            .map(std::collections::BTreeMap::len),
        Some(2)
    );
    assert_eq!(
        cfg.command
            .as_ref()
            .and_then(|s| s.approval.as_ref())
            .and_then(|a| a.block_wait),
        Some(false)
    );
}

#[test]
fn file_config_missing_and_empty_sections_are_legal() {
    for text in [
        "",
        "# 仅注释\n",
        "[audit]\n",
        "[audit]\n[storage]\n",
        "[server]\n[admin]\n[matrix]\n",
    ] {
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
            "[matrix]\nhomeserver = \"x\"\n[redaction]\nunknown_sub = true\n",
            "unknown_sub",
        ),
        (
            "[admin]\nenabled = true\nobservability_disable = true\n",
            "observability_disable",
        ),
        (
            "[credential]\ndefault_decision = \"allow\"\nauto_approve = \"deny\"\n",
            "auto_approve",
        ),
    ] {
        let err = parse(text).expect_err(&format!("未知键 {key} 须拒解析"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}

/// 旧分节本身已删除：`[auth]` / `[limits]` / `[keepass]` 表头即未知键
/// （旧键名逐一拒绝的用例见 `tests/legacy_removed.rs`）。
#[test]
fn removed_sections_reject_unknown_keys() {
    // 分节本身已删除：`deny_unknown_fields` 在顶层即拒，错误指名的是**分节名**
    // （`auth` / `limits` / `keepass`），这已足以让部署方定位。
    for section in ["auth", "limits", "keepass"] {
        let text = format!("[{section}]\nsome_new_key = 1\n");
        let err = parse(&text).expect_err(&format!("分节 {section} 须被拒"));
        assert!(
            err.to_string().contains(section),
            "错误信息须指名被删除的分节 {section}: {err}"
        );
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
            "[admin]\ncredential_admin_token = \"x\"\n",
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
    let legacy_key = "get_binary_secret";
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
        ("[audit]\ntimeout_secs = \"30\"\n", "timeout_secs"),
        ("[redaction]\nenabled = \"false\"\n", "enabled"),
        ("[admin]\nenabled = \"false\"\n", "enabled"),
        ("[credential.approval]\nblock_wait = 1\n", "block_wait"),
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
        "[server]\nsurface_mode = \"\"\n",
        "[server]\nsurface_mode = \"x\"\n",
        "[credential]\ndefault_decision = \"\"\n",
        "[credential]\ndefault_decision = \"x\"\n",
        "[pii_scope]\nmode = \"x\"\n",
        "[credential]\nvault_backend = \"x\"\n",
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

    let mut mapping_keys: Vec<String> = MAPPINGS
        .iter()
        .map(|m| m.key.to_string())
        .chain(FILE_ONLY_KEYS.iter().map(|key| (*key).to_string()))
        .collect();
    mapping_keys.sort();
    assert_eq!(mapping_keys, expected, "封闭映射表键集须与规范清单逐项相等");
    assert_eq!(MAPPINGS.len(), 48, "封闭映射表须恰 48 行");

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
        .chain(
            // 文件专属根下的标量键不产生逐键条目：其代表根必须出现在声明键集中。
            flattened_keys(&cfg)
                .into_iter()
                .filter(|key| file_only_root(key).is_some() && mapping_for(key).is_none()),
        )
        .collect();
    resolved_keys.sort();
    resolved_keys.dedup();
    assert_eq!(resolved_keys, expected, "每条声明键须有解析产物");
}

/// `server` 是文件专属根，但其下的 `surface_mode` 有 env 映射：`resolve_entries`
/// 必须先查 MAPPINGS 再退到根清单，否则该键会被整根跳过（R1）。
#[test]
fn surface_mode_resolved_through_mapping_not_file_only_root() {
    let cfg = parse("[server]\nlisten_addr = \"127.0.0.1:8877\"\nsurface_mode = \"llm_only\"\n")
        .expect("样例须可解析");
    let entries = resolve_entries(&cfg).expect("解析条目");
    assert!(
        entries.iter().all(|entry| entry.key != "server"),
        "listen_addr 属文件专属根，不得生成逐键条目"
    );
    let surface = entries
        .iter()
        .find(|entry| entry.key == "server.surface_mode")
        .expect("surface_mode 须有逐键条目（MAPPINGS 优先于根清单）");
    assert_eq!(surface.canonical_env.as_deref(), Some("VEIL_ENTRY_MODE"));
    assert_eq!(surface.value, "llm_only");
    assert_eq!(surface.env_explicit_names, vec!["VEIL_ENTRY_MODE"]);
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
    assert_eq!(names("server.surface_mode"), ["VEIL_ENTRY_MODE"].as_slice());
    assert_eq!(names("admin.enabled"), ["ADMIN_ENABLED"].as_slice());
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
         [credential]\ndefault_decision = \"allow\"\nvault_backend = \"mock\"\n\
         [server]\nsurface_mode = \"llm_only\"\n\
         [pii_scope]\nmode = \"conversation\"\n",
    )
    .expect("合法样例");
    assert_eq!(resolved_value(&cfg, "audit.mode"), "approve");
    assert_eq!(resolved_value(&cfg, "credential.default_decision"), "true");
    assert_eq!(resolved_value(&cfg, "server.surface_mode"), "llm_only");
    assert_eq!(resolved_value(&cfg, "pii_scope.mode"), "conversation");
    assert_eq!(resolved_value(&cfg, "credential.vault_backend"), "mock");
    for (raw, token) in [("deny", "false"), ("pending", "pending")] {
        let cfg = parse(&format!("[credential]\ndefault_decision = {raw:?}\n")).expect("合法样例");
        assert_eq!(resolved_value(&cfg, "credential.default_decision"), token);
    }
}

/// `surface_mode` 只接受两个规范拼写；0.1.x 的三个历史拼写按非法枚举值拒。
#[test]
fn surface_mode_rejects_historical_spellings() {
    for raw in LEGACY_SURFACE_MODES {
        assert!(
            parse(&format!("[server]\nsurface_mode = {raw:?}\n")).is_err(),
            "历史拼写 {raw:?} 须拒解析"
        );
    }
    for (raw, want) in [("full", "full"), ("llm_only", "llm_only")] {
        let cfg = parse(&format!("[server]\nsurface_mode = {raw:?}\n")).expect("规范拼写须可解析");
        assert_eq!(resolved_value(&cfg, "server.surface_mode"), want);
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

mod admin_polarity;
mod bindings;
mod docs_lockstep;
mod env_read_surface;
mod legacy_removed;
mod limits_hold;
mod merge;
mod redline;
mod secrets;
mod storage;
