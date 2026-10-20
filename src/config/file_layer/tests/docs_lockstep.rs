//! 锁步测试（tasks 5.1/5.4）：文件 schema ↔ 工程参考 §1「配置文件层（TOML）」
//! 子节键集、映射目标 ↔ env 读取名、别名概念 ↔ design D6 别名表、
//! `examples/veil.toml` ↔ schema 与密钥门禁。任一侧漂移即 `cargo test` 失败。

use {
    super::{ENV_PARSE_SRC, PII_SCOPE_SRC, TempFile, VALIDATE_SRC, flattened_keys},
    crate::config::{
        AutoApprove,
        Config,
        EntryMode,
        HeaderValueSegment,
        HeaderValueSpec,
        ParamProtocol,
        TargetKey,
        env_parse::test_support::base_env,
        env_surface::{CONFIG_ENV_WHITELIST, MIGRATED_ENV_VARS},
        file_layer::{
            BOOTSTRAP_VAR,
            FILE_ONLY_KEYS,
            FileConfig,
            MAPPINGS,
            MappingTarget,
            apply_config_file,
            declares_secret_keys,
            file_only_root,
        },
        targets::TARGETS_STRUCTURAL_KEYS,
    },
    std::collections::BTreeSet,
};

/// 工程参考（文档侧锁步真源）。
const ENGINEERING_REFERENCE: &str = include_str!("../../../../docs/engineering-reference.md");
/// 可加载示例（示例侧锁步真源）。
const EXAMPLE_TOML: &str = include_str!("../../../../examples/veil.toml");
/// 容器版示例（仅 `[server].bind` 与本机版不同）。
const CONTAINER_EXAMPLE_TOML: &str = include_str!("../../../../examples/veil.container.toml");

/// 文档侧子节标题（§1 内，非顶级 §N）。
const SUBSECTION_HEADING: &str = "### 配置文件层（TOML）";

/// 文件专属键在 schema 表第二列的标注（与 `FILE_ONLY_KEYS` 一一对应）。
const FILE_ONLY_ENV_LABEL: &str = "（文件专属）";

/// design D6「别名概念的 env 显式名集合」表（静态部分）。`AUDIT_ENABLED` 真值
/// 叠加与 `merge_entries` 的 audit 兼容分支已随 tasks 2.2 删除（见 design D3/D4）；
/// `[audit].mode` 的 env 显式名集合今为规范名 `AUDIT_MODE` 单项。
const D6_ALIAS_SETS: &[(&str, &[&str])] = &[
    (
        "redaction.enabled",
        &["REDACTION_ENABLED", "PII_REDACTION_ENABLED"],
    ),
    (
        "redaction.custom_rules_file",
        &[
            "PII_CUSTOM_RULES_FILE",
            "PII_RULES_FILE",
            "PII_CUSTOM_RULES",
        ],
    ),
    (
        "redaction.custom_patterns_file",
        &[
            "PII_CUSTOM_PATTERNS_FILE",
            "PII_CUSTOM_PATTERN_FILE",
            "PII_CUSTOM_PATTERNS",
        ],
    ),
    (
        "redaction.custom_dict_file",
        &[
            "PII_CUSTOM_DICT_FILE",
            "PII_DICT_FILE",
            "PII_SENSITIVE_DICT_FILE",
            "PII_SENSITIVE_NAMES_FILE",
            "PII_CUSTOM_DICT",
        ],
    ),
    ("audit.mode", &["AUDIT_MODE"]),
];

/// 直读/compose 专有 env 名：不属文件层可映射面（映射目标不得落入）。
const ENV_ONLY_EXCLUDED: &[&str] = &[
    "RUST_LOG",
    "VEIL_ALLOW_MOCK_TPM",
    "HOME",
    "PORT_8877",
    "PORT_8878",
    "PORT_8879",
    "TPM_HOST_PATH",
    "DB_HOST_PATH",
];

/// 工程参考 §1 子节文本（标题起、至下一个 `## ` 级标题前）。
fn doc_subsection() -> &'static str {
    let start = ENGINEERING_REFERENCE
        .find(SUBSECTION_HEADING)
        .expect("工程参考须含「配置文件层（TOML）」子节");
    let rest = &ENGINEERING_REFERENCE[start..];
    let end = rest[SUBSECTION_HEADING.len()..]
        .find("\n## ")
        .map_or(rest.len(), |offset| SUBSECTION_HEADING.len() + offset);
    &rest[..end]
}

/// 反引号包裹的单元格 → 内容；表头/分隔行返回 `None`。
fn backticked(cell: &str) -> Option<&str> { cell.trim().strip_prefix('`')?.strip_suffix('`') }

/// 文档侧 `[llm.targets]` 结构性键表：自 `| 结构键 | 出现层级 | 说明 |` 表头起，
/// 逐行取第一列（反引号键）与第二列（层级文本）为有序 `(层级, 键)` 二元组
/// （分隔行 `|:--|` 第一列非反引号，自然跳过；第二列须保持非反引号）。
fn doc_targets_structural_keys() -> Vec<(String, String)> {
    const HEADER: &str = "| 结构键 | 出现层级 | 说明 |";
    let lines: Vec<&str> = doc_subsection().lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == HEADER)
        .expect("工程参考 §1 须含「| 结构键 | 出现层级 | 说明 |」结构性键表头");
    let mut rows = Vec::new();
    for line in &lines[start + 1..] {
        let Some(row) = line.strip_prefix('|') else {
            break;
        };
        let mut cells = row.split('|').map(str::trim);
        if let (Some(key), Some(layer)) = (
            cells.next().and_then(backticked),
            cells.next().filter(|cell| !cell.is_empty()),
        ) {
            rows.push((layer.to_string(), key.to_string()));
        }
    }
    rows
}

/// 子节表格逐行解析为 `(文件键, 规范 env 名)`（第一列/第二列）。
fn doc_schema_rows() -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for line in doc_subsection().lines() {
        let Some(row) = line.strip_prefix('|') else {
            continue;
        };
        let mut cells = row.split('|').map(str::trim);
        let (Some(key), Some(env)) = (
            cells.next().and_then(backticked),
            cells.next().and_then(backticked),
        ) else {
            continue;
        };
        rows.push((key.to_string(), env.to_string()));
    }
    rows
}

/// 工程参考 §1「环境变量表」子节文本（标题起、至下一个 `### ` 级标题前）。
fn doc_env_vars_subsection() -> &'static str {
    const HEADING: &str = "### 环境变量表";
    let start = ENGINEERING_REFERENCE
        .find(HEADING)
        .expect("工程参考须含「环境变量表」子节");
    let rest = &ENGINEERING_REFERENCE[start..];
    let end = rest[HEADING.len()..]
        .find("\n### ")
        .map_or(rest.len(), |offset| HEADING.len() + offset);
    &rest[..end]
}

/// 「环境变量表」数据行的第一列（反引号变量名）；表头/分隔行/表外文本自然跳过。
fn doc_env_var_names() -> Vec<String> {
    const HEADER: &str = "| 变量 | 默认 | 说明 |";
    let section = doc_env_vars_subsection();
    let lines: Vec<&str> = section.lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == HEADER)
        .expect("工程参考 §1 须含「| 变量 | 默认 | 说明 |」环境变量表头");
    let mut names = Vec::new();
    for line in &lines[start + 1..] {
        let Some(row) = line.strip_prefix('|') else {
            break;
        };
        if let Some(name) = row.split('|').next().and_then(backticked) {
            names.push(name.to_string());
        }
    }
    names
}

/// 文档键集须与封闭映射表（`FileConfig` 键集的单一真源，见
/// `mapping_table_locked_to_schema_and_canonical_list`）逐项相等。
#[test]
fn doc_schema_key_set_equals_closed_mapping_table() {
    let documented = doc_schema_rows();
    let doc_keys: BTreeSet<String> = documented.iter().map(|(key, _)| key.clone()).collect();
    assert_eq!(
        documented.len(),
        doc_keys.len(),
        "工程参考 §1 子节键表不得出现重复行"
    );
    let mapping_keys: BTreeSet<String> = MAPPINGS
        .iter()
        .map(|m| m.key.to_string())
        .chain(FILE_ONLY_KEYS.iter().map(|key| (*key).to_string()))
        .collect();
    assert_eq!(
        doc_keys, mapping_keys,
        "工程参考 §1 子节键集须与封闭映射表 ∪ 文件专属键根逐项相等（任一侧增删须同步）"
    );
}

/// 文档侧 `[llm.targets]` 结构性键表须与 schema 侧闭集以有序 `(层级, 键)` 二元组
/// 逐项相等；同一键跨层级（目标级 `override` 与协议段 `override`）合法，仅二元组
/// 重复才判失败。
#[test]
fn doc_targets_structural_keys_match_schema_closed_list() {
    let doc_rows = doc_targets_structural_keys();
    assert!(!doc_rows.is_empty(), "结构性键表不得为空");
    let mut unique = doc_rows.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        doc_rows.len(),
        unique.len(),
        "结构性键表不得出现重复的 (层级, 键) 二元组: {doc_rows:?}"
    );
    let schema_rows: Vec<(String, String)> = TARGETS_STRUCTURAL_KEYS
        .iter()
        .flat_map(|(layer, keys)| {
            keys.iter()
                .map(|key| ((*layer).to_string(), (*key).to_string()))
        })
        .collect();
    assert_eq!(
        doc_rows, schema_rows,
        "工程参考 §1 结构性键表须与 TARGETS_STRUCTURAL_KEYS 有序二元组逐项相等（任一侧增删/改层级须同步）"
    );
}

/// 迁移清单等式（可机检）：`MIGRATED == (⋃ MAPPINGS.env_explicit_names) − WHITELIST`
/// 且恰 47 项。任一迁移名或其 MAPPINGS 映射增删即失败。
#[test]
fn migrated_list_equals_mapping_union_minus_whitelist() {
    let whitelist: BTreeSet<&str> = CONFIG_ENV_WHITELIST.iter().copied().collect();
    let union: BTreeSet<&str> = MAPPINGS
        .iter()
        .flat_map(|m| m.env_explicit_names.iter().copied())
        .collect();
    let want: BTreeSet<&str> = union.difference(&whitelist).copied().collect();
    let got: BTreeSet<&str> = MIGRATED_ENV_VARS.iter().copied().collect();
    assert_eq!(MIGRATED_ENV_VARS.len(), 47, "迁移清单须恰 47 项");
    assert_eq!(got.len(), 47, "迁移清单不得有重复项");
    assert_eq!(
        got, want,
        "迁移清单须等于「映射 env 显式名并集 − 白名单」（任一侧增删须同步）"
    );
}

/// 「环境变量表」须恰覆盖白名单 9 项，且不再声明 `LLM_<port>` 模式。
#[test]
fn env_var_table_equals_whitelist() {
    let whitelist: BTreeSet<String> = CONFIG_ENV_WHITELIST.iter().map(|s| s.to_string()).collect();
    let doc_names = doc_env_var_names();
    let doc_set: BTreeSet<String> = doc_names.iter().cloned().collect();
    assert_eq!(doc_names.len(), doc_set.len(), "环境变量表不得有重复行");
    assert_eq!(
        doc_set, whitelist,
        "「环境变量表」须恰覆盖白名单 9 项（任一侧增删须同步）"
    );
    assert!(
        !doc_env_vars_subsection().contains("`LLM_<port>`"),
        "`LLM_<port>` 已不属读取面，环境变量子节不得再声明该模式"
    );
}

/// 迁移概念文档覆盖：每个纯迁移映射的键行须在 §1 配置文件键表；每个迁移名须以
/// 规范名（键表第二列）成行或以「env 别名」注记归属（别名不要求单独成行）。
#[test]
fn config_key_table_covers_migrated_concepts_and_aliases() {
    let migrated: BTreeSet<&str> = MIGRATED_ENV_VARS.iter().copied().collect();
    let doc_rows = doc_schema_rows();
    let doc_keys: BTreeSet<&str> = doc_rows.iter().map(|(key, _)| key.as_str()).collect();
    let doc_envs: BTreeSet<&str> = doc_rows.iter().map(|(_, env)| env.as_str()).collect();
    let subsection = doc_subsection();

    for mapping in MAPPINGS {
        let MappingTarget::Env(name) = &mapping.target else {
            continue;
        };
        if !migrated.contains(name) {
            continue;
        }
        assert!(
            doc_keys.contains(mapping.key),
            "纯迁移映射 {}（目标 {name}）的键行须出现在 §1 配置文件键表",
            mapping.key
        );
    }

    for name in &migrated {
        let canonical = MAPPINGS
            .iter()
            .any(|m| matches!(&m.target, MappingTarget::Env(target) if target == name));
        if canonical {
            assert!(
                doc_envs.contains(name),
                "迁移概念规范名 {name} 须作为 §1 键表第二列成行"
            );
        } else {
            assert!(
                subsection.contains(name),
                "迁移别名 {name} 须在 §1 配置文件键表说明中以「env 别名」注记归属"
            );
        }
    }
}

/// 文档第二列的规范 env 名须与映射目标一致（含端口表的 `LLM_<port>` 展开形态）。
#[test]
fn doc_env_names_match_mapping_targets() {
    for (key, doc_env) in doc_schema_rows() {
        if file_only_root(&key).is_some() {
            assert_eq!(
                doc_env, FILE_ONLY_ENV_LABEL,
                "文件专属键 {key} 的说明列须为 {FILE_ONLY_ENV_LABEL:?}"
            );
            continue;
        }
        let mapping = MAPPINGS
            .iter()
            .find(|m| m.key == key)
            .unwrap_or_else(|| panic!("文档键 {key} 须在封闭映射表中"));
        let want: &str = match &mapping.target {
            MappingTarget::Env(name) => name,
            MappingTarget::PortTable => "LLM_<port>",
        };
        assert_eq!(doc_env, want, "文档键 {key} 的规范 env 名须与映射目标一致");
    }
}

/// 每个映射目标的规范 env 名须落在白名单 ∪ 迁移清单内（进程 env 面收敛后，映射
/// 目标要么是仍读 env 的白名单名、要么是已迁移概念的规范名），不属直读/compose
/// 专有面；端口表展开为 `LLM_<port>` 模式，天然落在白名单模式内。并须仍在 loader
/// 源码中以字面量出现——防「目标名与 env 显式名同步打错」造成的静默死键
/// （membership 断言在同文件锁步等式下可推导、无独立敏感性；见 oracle 实施复核）。
#[test]
fn mapping_targets_are_env_read_names() {
    let whitelist: BTreeSet<&str> = CONFIG_ENV_WHITELIST.iter().copied().collect();
    let migrated: BTreeSet<&str> = MIGRATED_ENV_VARS.iter().copied().collect();
    for mapping in MAPPINGS {
        let name = match &mapping.target {
            MappingTarget::Env(name) => *name,
            MappingTarget::PortTable => continue,
        };
        assert!(
            whitelist.contains(name) || migrated.contains(name),
            "映射目标 {name} 须为白名单名或迁移清单名：收敛后映射目标不得来自未知 env 面"
        );
        assert!(
            !ENV_ONLY_EXCLUDED.contains(&name),
            "映射目标 {name} 属直读/compose 专有 env 名，不得经文件层映射"
        );
        let needle = format!("\"{name}\"");
        assert!(
            ENV_PARSE_SRC.contains(&needle)
                || PII_SCOPE_SRC.contains(&needle)
                || VALIDATE_SRC.contains(&needle),
            "映射目标 {name} 须在 loader 源码（env_parse/pii_scope/validate）中以字面量出现：防死键"
        );
    }
}

/// 别名概念的 env 显式名集合须与 design D6 表逐项相等；非别名概念须恰为规范名。
#[test]
fn alias_env_explicit_sets_match_design_d6() {
    for (key, want) in D6_ALIAS_SETS {
        let mapping = MAPPINGS
            .iter()
            .find(|m| m.key == *key)
            .unwrap_or_else(|| panic!("design D6 别名概念 {key} 须在封闭映射表中"));
        assert_eq!(
            mapping.env_explicit_names, *want,
            "别名概念 {key} 的 env 显式名集合须与 design D6 逐项相等"
        );
    }
    for mapping in MAPPINGS {
        if D6_ALIAS_SETS.iter().any(|(key, _)| *key == mapping.key) {
            continue;
        }
        let want: &[&str] = match &mapping.target {
            MappingTarget::Env(name) => std::slice::from_ref(name),
            MappingTarget::PortTable => &[],
        };
        assert_eq!(
            mapping.env_explicit_names, want,
            "非别名概念 {} 的 env 显式名集合须恰为规范名",
            mapping.key
        );
    }
}

/// 示例文件：键集 ⊆ schema（含文件专属键根，**非全等**）、每个 schema 分节至少一个
/// 代表键、且不声明任何密钥类键（0644 可加载）。
#[test]
fn container_example_differs_only_in_server_bind_and_loads() {
    let local: FileConfig = toml::from_str(EXAMPLE_TOML).expect("本机示例须可解析");
    let container: FileConfig = toml::from_str(CONTAINER_EXAMPLE_TOML).expect("容器示例须可解析");
    let mut local_value = serde_json::to_value(&local).expect("本机示例序列化");
    let mut container_value = serde_json::to_value(&container).expect("容器示例序列化");
    assert_eq!(
        local_value["server"]["bind"],
        serde_json::json!("127.0.0.1:8877")
    );
    assert_eq!(
        container_value["server"]["bind"],
        serde_json::json!("0.0.0.0:8877")
    );
    local_value["server"]["bind"] = serde_json::json!("normalized");
    container_value["server"]["bind"] = serde_json::json!("normalized");
    assert_eq!(
        local_value, container_value,
        "两份示例除 [server].bind 外须逐项一致"
    );

    for (content, want) in [
        (EXAMPLE_TOML, "127.0.0.1:8877"),
        (CONTAINER_EXAMPLE_TOML, "0.0.0.0:8877"),
    ] {
        let file = TempFile::new("example-bind.toml", content);
        let mut env = base_env();
        env.insert(
            BOOTSTRAP_VAR.to_string(),
            file.path().to_string_lossy().into_owned(),
        );
        let outcome = apply_config_file(&mut env).expect("示例须可经引导加载");
        let cfg = Config::load_from_with_file(&env, outcome).expect("示例配置须可加载");
        assert_eq!(cfg.server_bind, want.parse().expect("SocketAddr 字面量"));
    }
}

#[test]
fn example_file_covers_all_sections_and_declares_no_secret_keys() {
    let cfg: FileConfig = toml::from_str(EXAMPLE_TOML).expect("示例文件须可解析为 FileConfig");
    assert!(
        !declares_secret_keys(&cfg),
        "示例文件不得声明任何密钥类键（0644 入库仍须可加载）"
    );
    let keys: BTreeSet<String> = flattened_keys(&cfg).into_iter().collect();
    let schema_keys: BTreeSet<String> = MAPPINGS
        .iter()
        .map(|m| m.key.to_string())
        .chain(FILE_ONLY_KEYS.iter().map(|key| (*key).to_string()))
        .collect();
    assert!(
        keys.is_subset(&schema_keys),
        "示例键须全部落在 schema（含文件专属键根）内，越界项: {:?}",
        keys.difference(&schema_keys).collect::<Vec<_>>()
    );
    let sections: BTreeSet<&str> = schema_keys
        .iter()
        .filter_map(|key| key.split('.').next())
        .collect();
    for section in sections {
        let prefix = format!("{section}.");
        assert!(
            keys.iter()
                .any(|key| key == section || key.starts_with(&prefix)),
            "示例文件分节 [{section}] 须至少一个代表键"
        );
    }
    assert!(
        keys.contains("llm.upstreams"),
        "示例须含 [llm.upstreams] 端口表"
    );
    assert!(
        keys.contains("llm.targets"),
        "示例须含 [llm.targets] 目标覆盖分节"
    );
}

/// 取 `HeaderValueSpec` 的静态值文本（模板返回 `None`）。
fn static_text(spec: &HeaderValueSpec) -> Option<&str> {
    match spec {
        HeaderValueSpec::Static(value) => value.to_str().ok(),
        HeaderValueSpec::Template(_) => None,
    }
}

/// 示例文件按 `0644`（Unix）落盘后经引导变量加载：不触发密钥门禁，且文件值生效。
fn example_temp_file() -> TempFile {
    #[cfg(unix)]
    {
        TempFile::with_mode("example-veil.toml", EXAMPLE_TOML, 0o644)
    }
    #[cfg(not(unix))]
    {
        TempFile::new("example-veil.toml", EXAMPLE_TOML)
    }
}

#[test]
fn example_file_loads_and_applies_from_disk() {
    let file = example_temp_file();
    let mut env = base_env();
    env.insert(
        BOOTSTRAP_VAR.to_string(),
        file.path().to_string_lossy().into_owned(),
    );
    let targets = apply_config_file(&mut env)
        .expect("示例文件须成功合并（不含密钥类键，0644 不触发门禁）")
        .llm_targets;
    let cfg = Config::load_from_with_targets(&env, targets).expect("示例文件须通过既有校验链");
    assert_eq!(cfg.pii_scope_ttl_secs, 3600);
    assert!(cfg.pii_detection_hardening);
    assert_eq!(cfg.entry_mode, EntryMode::Full);
    assert_eq!(cfg.auto_approve, AutoApprove::Pending);
    assert_eq!(
        cfg.llm_default_upstream.as_deref(),
        Some("http://127.0.0.1:11434")
    );
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://127.0.0.1:11435")
    );

    // 端口目标：头与三协议参数逐项生效（字段级）。
    let port = cfg
        .llm_targets
        .get(&TargetKey::Port(8878))
        .expect("示例须声明端口 8878 目标");
    assert_eq!(
        port.headers.get("anthropic-version").and_then(static_text),
        Some("2023-06-01")
    );
    assert_eq!(
        port.headers.get("x-upstream-feature").and_then(static_text),
        Some("port-8878")
    );
    assert!(
        port.override_existing,
        "8878 目标未声明 override，缺省须为恒胜"
    );
    let chat = port
        .params
        .get(&ParamProtocol::Chat)
        .expect("chat 子表须在");
    assert_eq!(
        chat.default.get("temperature"),
        Some(&serde_json::json!(0.7))
    );
    assert_eq!(chat.r#override.get("top_p"), Some(&serde_json::json!(0.9)));
    assert_eq!(chat.drop, vec!["presence_penalty".to_string()]);
    let anthropic = port
        .params
        .get(&ParamProtocol::Anthropic)
        .expect("anthropic 子表须在");
    assert_eq!(
        anthropic.r#override.get("max_tokens"),
        Some(&serde_json::json!(1024))
    );
    let responses = port
        .params
        .get(&ParamProtocol::Responses)
        .expect("responses 子表须在");
    assert_eq!(responses.drop, vec!["store".to_string()]);

    // default 目标：回退覆盖头生效。
    let default = cfg
        .llm_targets
        .get(&TargetKey::Default)
        .expect("示例须声明 default 目标");
    assert_eq!(
        default
            .headers
            .get("x-upstream-feature")
            .and_then(static_text),
        Some("default")
    );
    assert!(
        !default.override_existing,
        "default 目标声明 override = false，须为合并模式"
    );

    // opencode 兼容示例（8879）：UA 恒胜 + 合并模式身份头（含动态 `$conversation` 补齐）。
    let compat = cfg
        .llm_targets
        .get(&TargetKey::Port(8879))
        .expect("示例须声明端口 8879 opencode 兼容目标");
    assert_eq!(
        compat
            .user_agent
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("opencode/1.18.33"),
        "8879 目标须声明 UA 恒胜覆盖"
    );
    assert!(
        !compat.override_existing,
        "8879 目标须为合并模式（保留 opencode CLI 动态身份头）"
    );
    assert_eq!(
        compat
            .headers
            .get("x-opencode-client")
            .and_then(static_text),
        Some("cli"),
        "8879 目标须补齐 x-opencode-client 静态身份头"
    );
    let session = compat
        .headers
        .get("x-opencode-session")
        .expect("8879 目标须声明动态会话头（$conversation 模板）");
    assert_eq!(
        session,
        &HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
        "x-opencode-session 须预编译为单段 $conversation 模板"
    );

    for secret_env in [
        "VEILCTL_SECRET",
        "VEILCTL_BINARY_HASH",
        "PII_VALUE_SAMPLE_HMAC_KEY",
    ] {
        assert!(
            !env.contains_key(secret_env),
            "示例文件不得写入密钥类 env {secret_env}"
        );
    }
    assert!(cfg.veilctl_secret.is_none());
    assert!(cfg.veilctl_binary_hash.is_none());
    assert!(cfg.pii_value_sample_hmac_key.is_none());
}
