//! `PII_SCOPE_*` 配置测试（与既有配置测试同域，`crate::config::env_parse`）。

use {
    super::{
        PII_SCOPE_KEY_HEADER_DEFAULT,
        PII_SCOPE_MAX_CONVERSATIONS_DEFAULT,
        PII_SCOPE_TTL_SECS_DEFAULT,
        PiiScopeMode,
    },
    crate::config::env_parse::{Config, test_support::base_env},
};

#[test]
fn pii_scope_mode_defaults_to_request() {
    // 默认模式 = request（现行为，零行为变化）；其余三项取文档默认值。
    let cfg = Config::load_from(&base_env()).expect("基准环境须合法");
    assert_eq!(cfg.pii_scope_mode, PiiScopeMode::Request);
    assert!(!cfg.pii_scope_mode.is_conversation());
    assert_eq!(cfg.pii_scope_ttl_secs, PII_SCOPE_TTL_SECS_DEFAULT);
    assert_eq!(
        cfg.pii_scope_max_conversations,
        PII_SCOPE_MAX_CONVERSATIONS_DEFAULT
    );
    assert_eq!(cfg.pii_scope_key_header, PII_SCOPE_KEY_HEADER_DEFAULT);
}

#[test]
fn pii_scope_mode_invalid_rejected() {
    // 非法模式：拒启动且报错列明合法值。
    let mut env = base_env();
    env.insert("PII_SCOPE_MODE".to_string(), "bogus".to_string());
    let msg = Config::load_from(&env).unwrap_err().to_string();
    assert!(
        msg.contains("PII_SCOPE_MODE") && msg.contains("request/conversation"),
        "须指明变量与合法值，实际: {msg}"
    );
    // TTL / 上限非正整数：拒启动并指明变量。
    for raw in ["0", "-1", "abc"] {
        let mut env = base_env();
        env.insert("PII_SCOPE_TTL_SECS".to_string(), raw.to_string());
        let msg = Config::load_from(&env).unwrap_err().to_string();
        assert!(msg.contains("PII_SCOPE_TTL_SECS"), "{raw} 实际: {msg}");
        let mut env = base_env();
        env.insert("PII_SCOPE_MAX_CONVERSATIONS".to_string(), raw.to_string());
        let msg = Config::load_from(&env).unwrap_err().to_string();
        assert!(
            msg.contains("PII_SCOPE_MAX_CONVERSATIONS"),
            "{raw} 实际: {msg}"
        );
    }
    // 合法显式值生效。
    let mut env = base_env();
    env.insert("PII_SCOPE_MODE".to_string(), "conversation".to_string());
    env.insert("PII_SCOPE_TTL_SECS".to_string(), "60".to_string());
    env.insert("PII_SCOPE_MAX_CONVERSATIONS".to_string(), "8".to_string());
    env.insert("PII_SCOPE_KEY_HEADER".to_string(), "x-my-conv".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert!(cfg.pii_scope_mode.is_conversation());
    assert_eq!(cfg.pii_scope_ttl_secs, 60);
    assert_eq!(cfg.pii_scope_max_conversations, 8);
    assert_eq!(cfg.pii_scope_key_header, "x-my-conv");
}
