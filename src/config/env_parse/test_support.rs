//! 跨子模块测试共享：基准环境（其它子模块测试经
//! `crate::config::env_parse::test_support` 复用）。

use std::collections::HashMap;

pub(crate) fn base_env() -> HashMap<String, String> {
    HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!room:example.com".to_string()),
        (
            "MATRIX_ACCESS_TOKEN".to_string(),
            "syt_matrix_token_xxx".to_string(),
        ),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "admin-observability-token-0123456789abcdef".to_string(),
        ),
    ])
}
