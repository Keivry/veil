//! 自定义 PII 文件 fail-closed 加载：多格式解析 + 形态校验。

use {super::validate::config_error, crate::error::Result, std::path::PathBuf};

/// DB 选择结果：排序取末的 `.kdbx` + 同名 `.key`（存在才带）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKdbx {
    pub db_path: PathBuf,
    pub keyfile_path: Option<PathBuf>,
}

/// 扫描 `DB_DIR` 下 `*.kdbx`，排序取末位；同名 `.key` 优先；多库打 warn；无库返回 None。
/// 归属本模块：与自定义文件同属“磁盘文件 fail-closed 处理”。
pub fn resolve_kdbx(db_dir: &std::path::Path) -> Option<ResolvedKdbx> {
    let entries = std::fs::read_dir(db_dir).ok()?;
    let mut kdbx: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("kdbx"))
        })
        .collect();
    kdbx.sort();
    let db_path = kdbx.pop()?;
    if !kdbx.is_empty() {
        tracing::warn!(
            "DB_DIR 存在多个 .kdbx（{} 个），按排序取末位: {}",
            kdbx.len() + 1,
            db_path.display()
        );
    }
    let keyfile_path = db_path.with_extension("key").is_file().then(|| {
        let key = db_path.with_extension("key");
        tracing::debug!("使用同名 keyfile: {}", key.display());
        key
    });
    Some(ResolvedKdbx {
        db_path,
        keyfile_path,
    })
}
/// 自定义 PII 文件 fail-closed 加载：`vars` 按优先级依次命中（主文件变量优先，
/// 别名文件变量次之，短变量最后），三槽（rules/patterns/dict）相互叠加、互不排斥；
/// 首个非空命中即为生效路径。已配置但缺文件/不可读/解析失败/形态非法一律拒绝启动，
/// 报错指明实际命中的变量名；空文件（零字节/仅空白）仅 warn 不拒启动（零命中语义）。
/// 格式：JSON 优先；`.yaml`/`.yml` 后缀或类 YAML 内容走极简 YAML 子集；
/// `.txt` 后缀或字典类纯名单内容走 TXT 名单（每行一名，`#` 注释忽略）。
pub fn load_custom_file(
    get: &dyn Fn(&str) -> Option<String>,
    vars: &[&str],
) -> Result<Option<PathBuf>> {
    let (var, raw) = vars
        .iter()
        .filter_map(|v| get(v).filter(|s| !s.is_empty()).map(|s| (*v, s)))
        .next()
        .map_or(
            (
                vars.first().copied().unwrap_or("PII_CUSTOM_RULES_FILE"),
                String::new(),
            ),
            |(v, s)| (v, s),
        );
    if raw.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(&raw);
    if !path.is_file() {
        return Err(config_error(
            var,
            &format!("{var} 指向的文件不存在或不可读: {raw:?}，拒绝启动"),
        ));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        config_error(
            var,
            &format!("{var} 文件读取失败 {}: {e:?}，拒绝启动", path.display()),
        )
    })?;
    if text.trim().is_empty() {
        tracing::warn!(
            "{var} 文件 {} 为空，仅告警不拒启动（零命中语义）",
            path.display()
        );
        return Ok(Some(path));
    }
    let value = parse_custom_text(var, &path, &text)?;
    // TXT 空名单（全注释/空行）同样仅 warn。
    if value.as_array().is_some_and(|a| a.is_empty())
        && path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
    {
        tracing::warn!(
            "{var} 文件 {} 名单为空，仅告警不拒启动（零命中语义）",
            path.display()
        );
        return Ok(Some(path));
    }
    validate_custom_shape(var, &path, &value)?;
    Ok(Some(path))
}

/// 自定义文件多格式解析：JSON → 极简 YAML 子集 → TXT 名单（字典）。
/// 非字典槽的 TXT 内容按字符串数组解析后由形态校验拒绝（fail-closed）。
fn parse_custom_text(var: &str, path: &std::path::Path, text: &str) -> Result<serde_json::Value> {
    let is_dict = var.contains("DICT") || var.contains("NAMES");
    let ext_yaml = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"));
    let ext_txt = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("txt"));
    if ext_txt {
        return Ok(parse_txt_list(text));
    }
    if ext_yaml {
        return parse_yaml_subset(text).map_err(|e| {
            config_error(
                var,
                &format!("{var} 文件 {} YAML 解析失败: {e}，拒绝启动", path.display()),
            )
        });
    }
    // 无后缀：JSON 优先，失败则嗅探 YAML/TXT。
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => Ok(v),
        Err(json_err) => {
            let trimmed = text.trim_start();
            let looks_yaml = trimmed.starts_with('-')
                || trimmed.starts_with('{')
                || text.lines().any(|l| {
                    let t = l.trim();
                    !t.is_empty()
                        && !t.starts_with('#')
                        && !t.starts_with('{')
                        && !t.starts_with('[')
                        && t.contains(':')
                });
            if looks_yaml && let Ok(v) = parse_yaml_subset(text) {
                return Ok(v);
            }
            // 字典槽纯名单回退 TXT（无冒号/括号的 bare 行）。
            if is_dict && looks_txt_list(text) {
                return Ok(parse_txt_list(text));
            }
            Err(config_error(
                var,
                &format!(
                    "{var} 文件 JSON 解析失败 {}: {json_err}，拒绝启动",
                    path.display()
                ),
            ))
        }
    }
}

/// TXT 名单：每行一名，`#` 整行/行尾注释忽略，空行跳过。
fn parse_txt_list(text: &str) -> serde_json::Value {
    let mut out = Vec::new();
    for line in text.lines() {
        let no_comment = line.split('#').next().unwrap_or("").trim();
        if no_comment.is_empty() {
            continue;
        }
        out.push(serde_json::Value::String(no_comment.to_string()));
    }
    serde_json::Value::Array(out)
}

/// 是否像 TXT 纯名单（每有效行都不含 JSON/YAML 结构字符）。
fn looks_txt_list(text: &str) -> bool {
    let mut any = false;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        any = true;
        if t.contains(['{', '}', '[', ']', ':', '"', '\'']) || t.starts_with('-') {
            return false;
        }
    }
    any
}

fn strip_yaml_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// 极简 YAML 子集（无外部依赖，对标原仓解析语义的最小交集）：
/// 支持 `- name: foo` + `pattern: bar` 列表映射、`- somename` 字符串列表、
/// `key: value` 顶层映射；`#` 注释与空行忽略，超集 YAML 按解析失败 fail-closed。
fn parse_yaml_subset(text: &str) -> std::result::Result<serde_json::Value, String> {
    use serde_json::{Map, Value as V};
    let mut items: Vec<V> = Vec::new();
    let mut mapping = Map::new();
    let mut has_mapping_line = false;
    let mut has_list_line = false;
    let mut current: Option<Map<String, V>> = None;
    let flush = |current: &mut Option<Map<String, V>>, items: &mut Vec<V>| {
        if let Some(m) = current.take()
            && !m.is_empty()
        {
            items.push(V::Object(m));
        }
    };
    for (idx, raw_line) in text.lines().enumerate() {
        let no_comment = match raw_line.find('#') {
            Some(p) => &raw_line[..p],
            None => raw_line,
        };
        if no_comment.trim().is_empty() {
            continue;
        }
        let indent = no_comment.len() - no_comment.trim_start().len();
        let t = no_comment.trim();
        if let Some(dash_rest) = t.strip_prefix('-') {
            has_list_line = true;
            flush(&mut current, &mut items);
            let rest = dash_rest.trim();
            if rest.is_empty() {
                current = Some(Map::new());
                continue;
            }
            if let Some(colon) = rest.find(':') {
                let (k, v) = rest.split_at(colon);
                let v = v[1..].trim();
                if k.trim().is_empty() {
                    return Err(format!("第 {} 行键为空", idx + 1));
                }
                let mut m = Map::new();
                m.insert(k.trim().to_string(), V::String(strip_yaml_quotes(v)));
                current = Some(m);
            } else {
                items.push(V::String(strip_yaml_quotes(rest)));
                current = None;
            }
            continue;
        }
        if let Some(colon) = t.find(':') {
            let (k, v) = t.split_at(colon);
            let (k, v) = (k.trim(), v[1..].trim());
            if k.is_empty() || k.contains(' ') && indent == 0 && has_list_line {
                return Err(format!("第 {} 行形态非法: {t:?}", idx + 1));
            }
            if indent == 0 && current.is_none() && !has_list_line {
                // 顶层映射形态。
                has_mapping_line = true;
                mapping.insert(k.to_string(), V::String(strip_yaml_quotes(v)));
            } else {
                // 列表项续行（`  pattern: ...`）。
                if k.is_empty() {
                    return Err(format!("第 {} 行键为空", idx + 1));
                }
                match current.as_mut() {
                    Some(m) => {
                        m.insert(k.to_string(), V::String(strip_yaml_quotes(v)));
                    }
                    None => return Err(format!("第 {} 行缩进键无归属列表项: {t:?}", idx + 1)),
                }
            }
            continue;
        }
        return Err(format!("第 {} 行无法解析: {t:?}", idx + 1));
    }
    flush(&mut current, &mut items);
    if has_mapping_line && !has_list_line {
        return Ok(V::Object(mapping));
    }
    if !items.is_empty() {
        return Ok(V::Array(items));
    }
    if has_mapping_line {
        return Ok(V::Object(mapping));
    }
    Err("空 YAML 文档".to_string())
}

/// 自定义文件形态校验：规则/模式须为 `{name, pattern}` 数组（模式兼容 `{name: pattern}` 映射），
/// 字典须为 `{name[, type]}` 数组、`[string]` 数组或 `{name: type}` 映射；缺字段即拒启动。
fn validate_custom_shape(
    var: &str,
    path: &std::path::Path,
    value: &serde_json::Value,
) -> Result<()> {
    use serde_json::Value as V;
    let is_dict = var.contains("DICT") || var.contains("NAMES");
    match value {
        V::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let ok = match item {
                    V::Object(map) => {
                        let has_name = map
                            .get("name")
                            .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()));
                        if is_dict {
                            has_name
                                && map
                                    .get("type")
                                    .is_none_or(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                        } else {
                            has_name
                                && map
                                    .get("pattern")
                                    .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                        }
                    }
                    V::String(s) => is_dict && !s.is_empty(),
                    _ => false,
                };
                if !ok {
                    return Err(config_error(
                        var,
                        &format!(
                            "{var} 文件 {} 第 {i} 项形态非法（规则/模式须含 name+pattern，字典须含 name），拒绝启动",
                            path.display()
                        ),
                    ));
                }
            }
            Ok(())
        }
        V::Object(map) => {
            if is_dict {
                if map
                    .values()
                    .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                {
                    return Ok(());
                }
            } else if map
                .values()
                .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            {
                return Ok(());
            }
            Err(config_error(
                var,
                &format!(
                    "{var} 文件 {} 映射值须为非空字符串，拒绝启动",
                    path.display()
                ),
            ))
        }
        _ => Err(config_error(
            var,
            &format!("{var} 文件 {} 顶层须为数组或映射，拒绝启动", path.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::config::env_parse::{Config, test_support::base_env},
    };

    #[test]
    fn file_len_under_800_or_split() {
        // H2.1 红线看护（口径=文件总行，含测试与注释）：超 800 即失败，
        // 须按 H1 门面+子模块模板拆分，不得只改数字放行。
        const SELF_SRC: &str = include_str!("custom_file.rs");
        let lines = SELF_SRC.lines().count();
        assert!(
            lines <= 800,
            "custom_file.rs {lines} 行超 800 红线：须拆分（见 veil-review-followup-arch-hygiene H1/H2.1）"
        );
    }

    fn custom_tmp_file(name: &str, content: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("veil-config-test-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn custom_file_missing_rejects_startup_naming_var() {
        for var in [
            "PII_CUSTOM_RULES_FILE",
            "PII_CUSTOM_PATTERNS_FILE",
            "PII_CUSTOM_DICT_FILE",
            "PII_CUSTOM_RULES",
            "PII_CUSTOM_DICT",
        ] {
            let mut env = base_env();
            env.insert(
                var.to_string(),
                "/nonexistent/veil-custom-缺失.json".to_string(),
            );
            let err = Config::load_from(&env).unwrap_err();
            assert!(err.to_string().contains(var), "变量 {var} 报错须指明变量名");
        }
    }

    #[test]
    fn custom_file_parse_failure_and_bad_shape_rejects_startup() {
        // 非法 JSON。
        let bad = custom_tmp_file("bad.json", "{不是 json");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_PATTERNS_FILE".to_string(),
            bad.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_CUSTOM_PATTERNS_FILE"));
        // 缺 pattern 字段。
        let malformed = custom_tmp_file("malformed.json", r#"[{"name":"x"}]"#);
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            malformed.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("PII_CUSTOM_RULES_FILE"), "实际: {msg}");
        // 顶层非数组/映射。
        let scalar = custom_tmp_file("scalar.json", "42");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            scalar.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_CUSTOM_DICT_FILE"));
        for p in [bad, malformed, scalar] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn custom_file_valid_shape_allows() {
        let rules = custom_tmp_file(
            "rules.json",
            r#"[{"name":"ext-id","pattern":"EXT-\\d{6}"}]"#,
        );
        let patterns = custom_tmp_file("patterns.json", r#"{"p1":"bar\\d+"}"#);
        let dict = custom_tmp_file("dict.json", r#"[{"name":"张三丰","type":"name"}]"#);
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            rules.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_PATTERNS".to_string(),
            patterns.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
        assert_eq!(
            cfg.pii_custom_patterns_file.as_deref(),
            Some(patterns.as_path())
        );
        assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
        // 未配置时为 None。
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(cfg.pii_custom_rules_file.is_none());
        for p in [rules, patterns, dict] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn yaml_merged_files_load_ok() {
        let rules = custom_tmp_file(
            "compat-rules.yaml",
            "# 自定义规则\n- name: ext-id\n  pattern: EXT-\\d{6}\n- name: emp_no\n  pattern: (?P<emp_no>(?<![\\d])工号\\d{6}(?![\\d]))\n",
        );
        let patterns = custom_tmp_file(
            "compat-patterns.yaml",
            "p1: bar\\d+\n# 注释行\np2: foo\\d+\n",
        );
        let dict = custom_tmp_file("compat-dict.yaml", "- 张三丰\n- 李四\n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            rules.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_PATTERNS_FILE".to_string(),
            patterns.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
        assert_eq!(
            cfg.pii_custom_patterns_file.as_deref(),
            Some(patterns.as_path())
        );
        assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
        for p in [rules, patterns, dict] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn txt_allowlist_loads_ok_ignoring_comments() {
        let dict = custom_tmp_file(
            "compat-dict.txt",
            "# 敏感名单\n张三丰\n\n李四 # 行尾注释\n# 全行注释\n王五\n",
        );
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
        std::fs::remove_file(dict).ok();
    }

    #[test]
    fn four_aliases_each_take_effect() {
        let rules = custom_tmp_file("alias-a.json", r#"[{"name":"x1","pattern":"X1\\d+"}]"#);
        let patterns = custom_tmp_file("alias-b.json", r#"{"p1":"P1\\d+"}"#);
        let dict = custom_tmp_file("alias-c.json", r#"["张三"]"#);
        let dict2 = custom_tmp_file("alias-d.json", r#"["李四"]"#);
        for (var, path, check) in [
            ("PII_RULES_FILE", &rules, "rules"),
            ("PII_CUSTOM_PATTERN_FILE", &patterns, "patterns"),
            ("PII_SENSITIVE_DICT_FILE", &dict, "dict"),
            ("PII_SENSITIVE_NAMES_FILE", &dict2, "dict"),
        ] {
            let mut env = base_env();
            env.insert(var.to_string(), path.to_string_lossy().into_owned());
            let cfg = Config::load_from(&env).unwrap();
            match check {
                "rules" => assert_eq!(
                    cfg.pii_custom_rules_file.as_deref(),
                    Some(path.as_path()),
                    "{var}"
                ),
                "patterns" => assert_eq!(
                    cfg.pii_custom_patterns_file.as_deref(),
                    Some(path.as_path()),
                    "{var}"
                ),
                _ => assert_eq!(
                    cfg.pii_custom_dict_file.as_deref(),
                    Some(path.as_path()),
                    "{var}"
                ),
            }
        }
        for p in [rules, patterns, dict, dict2] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn three_vars_overlay_primary_file_wins_coexist() {
        let merged = custom_tmp_file(
            "overlay-merged.json",
            r#"[{"name":"m1","pattern":"M1\\d+"}]"#,
        );
        let alias = custom_tmp_file(
            "overlay-alias.json",
            r#"[{"name":"a1","pattern":"A1\\d+"}]"#,
        );
        let short = custom_tmp_file(
            "overlay-short.json",
            r#"[{"name":"s1","pattern":"S1\\d+"}]"#,
        );
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            merged.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_RULES_FILE".to_string(),
            alias.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_RULES".to_string(),
            short.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(merged.as_path()));
        let patterns = custom_tmp_file("overlay-p.json", r#"{"pp":"PP\\d+"}"#);
        let dict = custom_tmp_file("overlay-d.json", r#"["赵六"]"#);
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            merged.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_PATTERNS_FILE".to_string(),
            patterns.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.pii_custom_rules_file.is_some());
        assert!(cfg.pii_custom_patterns_file.is_some());
        assert!(cfg.pii_custom_dict_file.is_some());
        let mut env = base_env();
        env.insert(
            "PII_SENSITIVE_DICT_FILE".to_string(),
            "/nonexistent/veil-别名缺失.json".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_SENSITIVE_DICT_FILE"));
        for p in [merged, alias, short, patterns, dict] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn empty_file_zero_hits_warns_and_allows() {
        let empty = custom_tmp_file("compat-empty.json", "   \n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            empty.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(empty.as_path()));
        let comments_only = custom_tmp_file("compat-comments.txt", "# 只有注释\n# 无名单\n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            comments_only.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.pii_custom_dict_file.as_deref(),
            Some(comments_only.as_path())
        );
        std::fs::remove_file(empty).ok();
        std::fs::remove_file(comments_only).ok();
    }

    #[test]
    fn yaml_bad_shape_rejects_startup() {
        let bad = custom_tmp_file("compat-bad.yaml", ":\n: :\n- \n???\n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            bad.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_CUSTOM_RULES_FILE"));
        std::fs::remove_file(bad).ok();
    }

    #[test]
    fn example_yaml_loads_on_startup() {
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            "examples/pii-custom.yaml".to_string(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.pii_custom_rules_file.as_deref(),
            Some(std::path::Path::new("examples/pii-custom.yaml"))
        );
    }

    #[test]
    fn multi_db_sorted_last_with_matching_key_preferred() {
        let dir = std::env::temp_dir().join(format!(
            "veil-resolve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.kdbx"), b"a").unwrap();
        std::fs::write(dir.join("z.kdbx"), b"z").unwrap();
        std::fs::write(dir.join("z.key"), b"key").unwrap();
        let found = resolve_kdbx(&dir).expect("须选中末位库");
        assert_eq!(found.db_path, dir.join("z.kdbx"));
        assert_eq!(found.keyfile_path, Some(dir.join("z.key")));
        std::fs::remove_file(dir.join("z.key")).unwrap();
        let found = resolve_kdbx(&dir).expect("无 keyfile 仍选中库");
        assert_eq!(found.db_path, dir.join("z.kdbx"));
        assert_eq!(found.keyfile_path, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_db_returns_none() {
        let dir = std::env::temp_dir().join(format!(
            "veil-resolve-empty-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("note.txt"), b"x").unwrap();
        assert!(resolve_kdbx(&dir).is_none());
        assert!(resolve_kdbx(&dir.join("不存在的子目录")).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
