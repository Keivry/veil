//! `DCD-6` YAML 去引号单一实现等价性单测（独立子模块保 `custom_file.rs` 800 行红线）：
//! `strip_yaml_quotes` 与合并前 `unquote`/同名副本逐例一致，成对引号剥离 + trim 不变。

use crate::config::custom_file::strip_yaml_quotes;

#[test]
fn yaml_unquote_equivalence() {
    // 合并前的 `unquote`/`strip_yaml_quotes` 两份实现逐字节相同；此处以参考实现对照
    // 锁定单一实现等价：成对引号剥离 + trim，不成对/空白/转义序列原样保留。
    fn reference(s: &str) -> String {
        let s = s.trim();
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\'')))
        {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    }
    let cases: &[(&str, &str)] = &[
        ("\"quoted\"", "quoted"),
        ("'single'", "single"),
        ("  \"padded\"  ", "padded"),
        ("  'padded'  ", "padded"),
        ("unquoted", "unquoted"),
        ("  unquoted  ", "unquoted"),
        ("\"", "\""),
        ("''", ""),
        ("", ""),
        ("   ", ""),
        ("\"mismatch'", "\"mismatch'"),
        ("'mismatch\"", "'mismatch\""),
        ("\"a\\\"b\"", "a\\\"b"),
        ("'it''s'", "it''s"),
        ("\"\"", ""),
        ("x\"y\"", "x\"y\""),
    ];
    for (input, expected) in cases {
        assert_eq!(
            strip_yaml_quotes(input),
            reference(input),
            "strip_yaml_quotes({input:?}) 与参考实现不等价"
        );
        assert_eq!(
            strip_yaml_quotes(input),
            *expected,
            "strip_yaml_quotes({input:?}) 行为漂移"
        );
    }
}
