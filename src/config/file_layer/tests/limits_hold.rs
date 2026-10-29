//! `[audit].hold_max_*` 双维度上限与 `[llm]` 两个字节上限的文件层单测：
//! TOML 类型拒收、越界值沿用 env 校验（`0` 一律拒启动）、负值在反序列化阶段
//! 即失败（tasks 6.1 至 6.3）。

use super::*;

#[test]
fn audit_hold_type_errors_rejected() {
    // 浮点类型在 toml 解析阶段即被拒（四键同口径），错误信息须指名键路径。
    for (text, key) in [
        ("[audit]\nhold_max_bytes = 1.5\n", "hold_max_bytes"),
        ("[audit]\nhold_max_frames = 1.5\n", "hold_max_frames"),
        ("[llm]\nnonstream_max_bytes = 1.5\n", "nonstream_max_bytes"),
        (
            "[llm]\nsse_frame_hard_bytes = 1.5\n",
            "sse_frame_hard_bytes",
        ),
    ] {
        let err = parse(text).expect_err(&format!("类型错误 {key} 须被拒"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}

#[test]
fn audit_hold_bounds_reuse_env_validation() {
    // 文件层 `0` 不得静默回落默认值：沿用 env 侧 `parse_positive_u64` 并拒启动。
    for (content, var) in [
        ("[audit]\nhold_max_bytes = 0\n", "AUDIT_HOLD_MAX_BYTES"),
        ("[audit]\nhold_max_frames = 0\n", "AUDIT_HOLD_MAX_FRAMES"),
        ("[llm]\nnonstream_max_bytes = 0\n", "NONSTREAM_MAX_BYTES"),
        ("[llm]\nsse_frame_hard_bytes = 0\n", "SSE_FRAME_HARD_BYTES"),
    ] {
        let file = TempFile::new("limits-bounds.toml", content);
        let mut env = with_config_file(&file);
        apply_only(&mut env);
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains(var),
            "文件值越界须沿用既有 env 校验并指名 {var}: {err}"
        );
    }
}

/// 负值在反序列化阶段失败（`u64` 类型边界），错误文本须含 `u64` 或 `invalid value`。
#[test]
fn negative_timeout_fails_at_deserialization_with_type_text() {
    for text in [
        "[audit]\ntimeout_secs = -1\n",
        "[pii_scope]\nttl_secs = -1\n",
        "[audit]\nhold_max_bytes = -1\n",
        "[llm]\nnonstream_max_bytes = -1\n",
        "[credential.authorization]\nttl_secs = -1\n",
        "[request_log]\nretention_days = -1\n",
    ] {
        let err = parse(text).expect_err(&format!("负值须在反序列化阶段失败: {text:?}"));
        let msg = err.to_string();
        assert!(
            msg.contains("invalid value") || msg.contains("u64"),
            "错误文本须陈述类型信息（u64 / invalid value）: {msg}"
        );
    }
}

/// `audit.timeout_secs = 0` 拒启动（`>= 1` 校验），错误文本不变。
#[test]
fn audit_timeout_zero_rejects_at_validation() {
    let file = TempFile::new("audit-zero.toml", "[audit]\ntimeout_secs = 0\n");
    let mut env = with_config_file(&file);
    apply_only(&mut env);
    let err = Config::load_from(&env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("AUDIT_TIMEOUT_SECS") && msg.contains("≥1"),
        "0 须沿用 env 校验并指名变量: {msg}"
    );
}

/// `pii_scope.ttl_secs = 0` 拒启动（`parse_positive_u64` 要 ≥ 1）。
#[test]
fn pii_scope_ttl_zero_rejects() {
    let file = TempFile::new("pii-ttl-zero.toml", "[pii_scope]\nttl_secs = 0\n");
    let mut env = with_config_file(&file);
    apply_only(&mut env);
    let err = Config::load_from(&env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("PII_SCOPE_TTL_SECS"),
        "pii_scope.ttl_secs=0 须拒启动并指名变量: {msg}"
    );
}

/// `audit.timeout_secs` 的 110-130 竞态区间校验仍生效且错误文本指名新键。
#[test]
fn audit_timeout_race_zone_names_new_key() {
    for raw in ["110", "120", "130"] {
        let file = TempFile::new(
            "audit-race.toml",
            &format!("[audit]\ntimeout_secs = {raw}\n"),
        );
        let mut env = with_config_file(&file);
        apply_only(&mut env);
        let msg = Config::load_from(&env).unwrap_err().to_string();
        assert!(
            msg.contains("AUDIT_TIMEOUT_SECS") && msg.contains("110-130"),
            "竞态区间 {raw} 须拒启动并指名新键: {msg}"
        );
    }
}

#[test]
fn file_layer_has_no_i64_fields() {
    // 文件层的可选整数字段已统一为 u64；拼接成串以免本机检文本自身命中。
    let needle = ["Option", "<", "i", "64", ">"].concat();
    for src in [
        include_str!("../../file_layer/sections.rs"),
        include_str!("../../file_layer/storage.rs"),
    ] {
        assert!(!src.contains(&needle), "文件层不得再有 i64 可选字段");
    }
}
