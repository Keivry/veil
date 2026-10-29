//! `[server]` 两键单测（`listen_addr` 与 `surface_mode`；tasks 3.1/3.2）。

use super::*;

#[test]
fn server_listen_addr_feeds_config_outcome() {
    let file = TempFile::new(
        "server-bind.toml",
        "[server]\nlisten_addr = \"0.0.0.0:8877\"\n",
    );
    let mut env = with_config_file(&file);
    let outcome = apply_config_file(&mut env).expect("[server].listen_addr 须可加载");
    assert_eq!(
        outcome.server_bind,
        Some("0.0.0.0:8877".parse().expect("SocketAddr 字面量"))
    );
    let cfg = Config::load_from_with_file(&env, outcome).expect("合并后配置须可加载");
    assert_eq!(cfg.server_bind, "0.0.0.0:8877".parse().unwrap());
}

#[test]
fn server_listen_addr_absent_falls_back_to_loopback_default() {
    let cfg = Config::load_from(&base_env()).expect("基线配置须合法");
    assert_eq!(cfg.server_bind, crate::config::DEFAULT_SERVER_BIND);
}

/// 错误文本须指名 `server.listen_addr`（而非旧的 `server.bind`）。
#[test]
fn server_listen_addr_rejects_invalid_values_with_key_name() {
    for value in ["\"8877\"", "\"127.0.0.1:70000\"", "\"not-an-addr\"", "8877"] {
        let file = TempFile::new(
            "server-bind-bad.toml",
            &format!("[server]\nlisten_addr = {value}\n"),
        );
        let mut env = with_config_file(&file);
        let err = apply_config_file(&mut env).unwrap_err();
        assert!(
            err.to_string().contains("server.listen_addr"),
            "非法 listen_addr {value} 须指名 server.listen_addr: {err}"
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

/// 旧键 `server.bind` 已随别名层移除：引导加载直接 fail-closed 拒启动并指名该键。
#[test]
fn legacy_server_bind_rejected_at_bootstrap() {
    let file = TempFile::new(
        "server-bind-legacy.toml",
        "[server]\nbind = \"0.0.0.0:8878\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("旧键须拒启动");
    let message = err.to_string();
    assert!(
        message.contains("bind"),
        "错误须指名被拒的旧键 bind: {message}"
    );
    assert!(
        message.contains("unknown field"),
        "旧键须以未知键拒绝（不得被归一后接受）: {message}"
    );
}

/// 旧键与新键并存同样拒启动（无优先级裁决，旧键本身就是未知键）。
#[test]
fn legacy_and_new_listen_addr_coexist_rejected() {
    let file = TempFile::new(
        "server-bind-conflict.toml",
        "[server]\nbind = \"0.0.0.0:8877\"\nlisten_addr = \"127.0.0.1:8877\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("bind"), "错误须指名旧键 bind: {msg}");
}

/// `command.approval.block_wait` 与 `credential.approval.block_wait` 可分别设置、互不影响
/// （tasks 3.4）。
#[test]
fn command_and_credential_block_wait_are_independent() {
    for (command_wait, credential_wait) in
        [(true, false), (false, true), (true, true), (false, false)]
    {
        let file = TempFile::new(
            "block-wait.toml",
            &format!(
                "[command]\nenabled = false\n[command.approval]\nblock_wait = {command_wait}\n\
                 [credential.approval]\nblock_wait = {credential_wait}\n"
            ),
        );
        let mut env = with_config_file(&file);
        let cfg = apply_and_load(&mut env);
        assert_eq!(
            cfg.command.block_wait, command_wait,
            "command.approval.block_wait 须独立生效"
        );
        assert_eq!(
            cfg.credential_block_wait, credential_wait,
            "credential.approval.block_wait 须独立生效（不受 command 影响）"
        );
    }
}

/// 两处旧键（`command.block_wait` / `storage.credential_block_wait`）均已移除，
/// 各自单独出现时即拒启动并指名该键。
#[test]
fn legacy_block_wait_keys_rejected() {
    for (text, needle) in [
        (
            "[command]\nenabled = false\nblock_wait = true\n",
            "block_wait",
        ),
        (
            "[storage]\ncredential_block_wait = false\n",
            "credential_block_wait",
        ),
    ] {
        let file = TempFile::new("legacy-block-wait.toml", text);
        let mut env = with_config_file(&file);
        let err = apply_config_file(&mut env).expect_err("旧键须拒启动");
        let message = err.to_string();
        assert!(
            message.contains(needle),
            "错误须指名旧键 {needle}: {message}"
        );
    }
}

/// `surface_mode` 只接受两个规范拼写；三个历史拼写在文件层即拒。
#[test]
fn surface_mode_alias_spellings_rejected() {
    for legacy in LEGACY_SURFACE_MODES {
        let file = TempFile::new(
            "surface-mode-legacy.toml",
            &format!("[server]\nsurface_mode = {legacy:?}\n"),
        );
        let mut env = with_config_file(&file);
        let err =
            apply_config_file(&mut env).expect_err(&format!("surface_mode = {legacy:?} 须拒启动"));
        let message = err.to_string();
        assert!(
            message.contains("surface_mode") || message.contains(legacy),
            "错误须指名 surface_mode 或旧拼写 {legacy}: {message}"
        );
    }
    for legacy in LEGACY_SURFACE_MODES {
        let err = parse(&format!("[server]\nsurface_mode = {legacy:?}\n"))
            .expect_err(&format!("文件层须拒 {legacy:?}"));
        assert!(err.to_string().contains(legacy), "{err}");
    }
}

/// 规范拼写仍生效，且 env 显式恒胜文件值。
#[test]
fn surface_mode_canonical_spellings_feed_entry_mode() {
    for (text, want) in [
        (
            "[server]\nsurface_mode = \"llm_only\"\n",
            EntryMode::LlmOnly,
        ),
        ("[server]\nsurface_mode = \"full\"\n", EntryMode::Full),
    ] {
        let file = TempFile::new("surface-mode.toml", text);
        let mut env = with_config_file(&file);
        let cfg = apply_and_load(&mut env);
        assert_eq!(cfg.surface_mode, want, "样例 {text:?} 须得 {want:?}");

        let mut env = with_config_file(&file);
        env.insert("VEIL_ENTRY_MODE".to_string(), "full".to_string());
        let cfg = apply_and_load(&mut env);
        assert_eq!(cfg.surface_mode, EntryMode::Full, "env 显式须恒胜");
    }
}
