//! `[server].bind` 文件层单测（自 `tests.rs` 拆出保持红线内）。

use super::*;

#[test]
fn server_bind_section_feeds_config_outcome() {
    let file = TempFile::new("server-bind.toml", "[server]\nbind = \"0.0.0.0:8877\"\n");
    let mut env = with_config_file(&file);
    let outcome = apply_config_file(&mut env).expect("[server].bind 须可加载");
    assert_eq!(
        outcome.server_bind,
        Some("0.0.0.0:8877".parse().expect("SocketAddr 字面量"))
    );
    let cfg = Config::load_from_with_file(&env, outcome).expect("合并后配置须可加载");
    assert_eq!(cfg.server_bind, "0.0.0.0:8877".parse().unwrap());
}

#[test]
fn server_bind_absent_falls_back_to_loopback_default() {
    let cfg = Config::load_from(&base_env()).expect("基线配置须合法");
    assert_eq!(cfg.server_bind, crate::config::DEFAULT_SERVER_BIND);
}

#[test]
fn server_bind_rejects_invalid_values_with_key_name() {
    for value in ["\"8877\"", "\"127.0.0.1:70000\"", "\"not-an-addr\"", "8877"] {
        let file = TempFile::new(
            "server-bind-bad.toml",
            &format!("[server]\nbind = {value}\n"),
        );
        let mut env = with_config_file(&file);
        let err = apply_config_file(&mut env).unwrap_err();
        assert!(
            err.to_string().contains("server.bind"),
            "非法 bind {value} 须指名 server.bind: {err}"
        );
    }
}

#[test]
fn server_section_rejects_unknown_keys() {
    let file = TempFile::new("server-unknown.toml", "[server]\nfoo = 1\n");
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).unwrap_err();
    assert!(
        err.to_string().contains("foo"),
        "未知键须被 deny_unknown_fields 拒绝: {err}"
    );
}
