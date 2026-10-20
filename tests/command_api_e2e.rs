//! 命令 API e2e：认证/授权、目录、自动放行、审批双模与幂等重入、日志查询。

mod common;

use {
    common::*,
    serde_json::{Value, json},
    std::{path::PathBuf, sync::atomic::AtomicU64},
    veil::{
        config::{CommandConfig, FileConfig, command::validate_command},
        registry::RegisterParams,
        service::AppStateParts,
        state::AppState,
    },
};

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "veil-cmd-e2e-{}-{tag}-{}",
        std::process::id(),
        DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn script(dir: &std::path::Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("run.sh");
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

const COUNTER_SCRIPT: &str = "#!/bin/sh\nsleep 0.2\necho ran >> counter.log\necho ok\nexit 0\n";
const FAIL_SCRIPT: &str = "#!/bin/sh\necho boom >&2\nexit 3\n";

fn command_config(dir: &std::path::Path, body: &str, requires_approval: bool) -> CommandConfig {
    let program = script(dir, body);
    let text = format!(
        r#"
[command]
enabled = true
block_wait = false

[command.hosts.api]
kind = "local"
[command.hosts.web]
kind = "local"

[command.groups.fleet]
hosts = ["api", "web"]

[command.commands.run]
program = "{program}"
args = ["--target", "{{target}}"]
usage = "run --target <host>"
hosts = ["fleet"]
timeout_secs = 10
requires_approval = {requires_approval}

[command.commands.run.parameters.target]
kind = "enum"
values = ["api", "web"]

[command.downstreams.ci]
callers = ["/opt/ci/agent.sh"]
allow_commands = ["run"]
"#,
        program = program.display(),
    );
    let parsed: FileConfig = toml::from_str(&text).expect("命令配置须可解析");
    validate_command(parsed.command.as_ref()).expect("命令配置须通过校验")
}

fn disabled_config() -> CommandConfig { CommandConfig::default() }

fn config_with_auto_approve(dir: &std::path::Path, body: &str) -> CommandConfig {
    let mut cfg = command_config(dir, body, true);
    if let Some(downstream) = cfg.downstreams.get_mut("ci") {
        downstream.auto_approve = vec![veil::config::command::AutoApproveRule {
            command: "run".to_string(),
            hosts: vec!["fleet".to_string()],
        }];
    }
    cfg
}

/// 从 TOML 解析：`run` 不声明 `requires_approval`，验证缺省为 true。
fn config_without_requires_approval(dir: &std::path::Path, body: &str) -> CommandConfig {
    let program = script(dir, body);
    let text = format!(
        r#"
[command]
enabled = true

[command.hosts.api]
kind = "local"

[command.commands.run]
program = "{program}"
args = ["--target", "{{target}}"]
usage = "run --target <host>"
hosts = ["api"]
timeout_secs = 10

[command.commands.run.parameters.target]
kind = "enum"
values = ["api"]

[command.downstreams.ci]
callers = ["/opt/ci/agent.sh"]
allow_commands = ["run"]
"#,
        program = program.display(),
    );
    let parsed: FileConfig = toml::from_str(&text).expect("命令配置须可解析");
    let cfg = validate_command(parsed.command.as_ref()).expect("命令配置须通过校验");
    assert!(
        cfg.commands["run"].requires_approval,
        "未声明 requires_approval 须缺省为 true"
    );
    cfg
}

fn app(dir: &std::path::Path, cfg: CommandConfig) -> (axum::Router, AppState) {
    let data_dir = dir.to_path_buf();
    test_app(TestOpts::new(&[]).db(dir.join("metrics.sqlite")).cfg_mut(
        move |config: &mut veil::config::Config| {
            config.data_dir = data_dir.clone();
            config.command = cfg;
        },
    ))
}

async fn enroll(state: &AppState, path: &str, hash: &str) {
    veil::service::credential::register_caller_extended(
        state,
        &RegisterParams {
            caller_path: path.to_string(),
            caller_hash: hash.to_string(),
            name: path.to_string(),
            ..RegisterParams::default()
        },
        &format!("cmd-e2e-{path}"),
    )
    .await
    .expect("注册须成功");
    state
        .registry
        .write()
        .await
        .set_enabled(path, true)
        .unwrap();
}

fn auth_headers(hash: &str) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "x-veilctl-binary-hash",
        VEILCTL_BINARY_HASH.parse().unwrap(),
    );
    headers.insert("x-veilctl-secret", VEILCTL_SECRET.parse().unwrap());
    headers.insert("x-caller-hash", hash.parse().unwrap());
    headers.insert("x-caller-path", "/opt/ci/agent.sh".parse().unwrap());
    headers
}

fn invoke_body(host: &str) -> Value {
    json!({"target": {"host": host}, "params": {"target": "api"}})
}

#[tokio::test]
async fn disabled_command_surface_returns_404() {
    let dir = temp_dir("disabled");
    let (app, _state) = app(&dir, disabled_config());
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/commands"))
        .headers(auth_headers("hash-ci"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 404, "body={body}");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn catalog_requires_deploy_secret() {
    let dir = temp_dir("nosecret");
    let (app, _state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/commands"))
        .header("x-caller-hash", "hash-ci")
        .header("x-caller-path", "/opt/ci/agent.sh")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn catalog_empty_for_unbound_caller() {
    let dir = temp_dir("unbound");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/other/agent.sh", "hash-other").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let mut headers = auth_headers("hash-other");
    headers.insert("x-caller-path", "/opt/other/agent.sh".parse().unwrap());
    let body: Value = client
        .get(format!("{base}/commands"))
        .headers(headers)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["commands"].as_array().unwrap().len(), 0);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn catalog_lists_allowed_commands() {
    let dir = temp_dir("catalog");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let body: Value = client
        .get(format!("{base}/commands"))
        .headers(auth_headers("hash-ci"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let commands = body["commands"].as_array().unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0]["id"], "run");
    assert_eq!(commands[0]["hosts"], json!(["api", "web"]));
    assert_eq!(commands[0]["parameters"]["target"]["kind"], "enum");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn auto_approved_invoke_executes_and_logs() {
    let dir = temp_dir("auto");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["exit_code"], 0);
    assert_eq!(body["stdout"].as_str().unwrap().trim_end(), "ok");
    assert!(dir.join("command-work").join("counter.log").exists());

    let page = state.command().log.query(Default::default()).await.unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0]["approval_status"], "not_required");
    assert_eq!(page.items[0]["exec_status"], "executed");
    assert!(page.items[0]["approval_event_id"].is_null());
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn group_target_rejected_400() {
    let dir = temp_dir("group");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("fleet"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn out_of_range_host_rejected_403() {
    let dir = temp_dir("range");
    let mut cfg = command_config(&dir, COUNTER_SCRIPT, false);
    if let Some(def) = cfg.commands.get_mut("run") {
        def.hosts = vec!["api".to_string()];
    }
    let (app, state) = app(&dir, cfg);
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("web"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn command_outside_allow_list_rejected_403() {
    let dir = temp_dir("allow");
    let mut cfg = command_config(&dir, COUNTER_SCRIPT, false);
    let program = cfg.commands.get("run").unwrap().program.clone();
    cfg.commands.insert(
        "other".to_string(),
        veil::config::CommandDef {
            program,
            args: Vec::new(),
            usage: "other".to_string(),
            description: String::new(),
            hosts: vec!["fleet".to_string()],
            timeout_secs: 10,
            requires_approval: false,
            parameters: Default::default(),
        },
    );
    let (app, state) = app(&dir, cfg);
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/other/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn undeclared_param_rejected_400() {
    let dir = temp_dir("param");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&json!({"target": {"host": "api"}, "params": {"target": "api", "extra": "x"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&json!({"target": {"host": "api"}, "params": {"target": "db"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unregistered_caller_not_auto_approved() {
    let dir = temp_dir("unregistered");
    let (app, _state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-unknown"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    assert!(!dir.join("command-work").join("counter.log").exists());
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn approval_then_reentry_executes_exactly_once() {
    let dir = temp_dir("approval");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);

    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state.approval.resolve(&event_id, "", true).await;

    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "body={body}");
    assert_eq!(body["exit_code"], 0);

    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "重复重入返回同一终态");

    let runs = std::fs::read_to_string(dir.join("command-work").join("counter.log")).unwrap();
    assert_eq!(runs.lines().count(), 1, "同一次审批至多执行一次");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn concurrent_reentry_executes_exactly_once() {
    let dir = temp_dir("concurrent");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state.approval.resolve(&event_id, "", true).await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let url = format!("{base}/commands/run/invoke");
        let headers = auth_headers("hash-ci");
        tasks.push(tokio::spawn(async move {
            client
                .post(url)
                .headers(headers)
                .json(&invoke_body("api"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 200);
    }
    let runs = std::fs::read_to_string(dir.join("command-work").join("counter.log")).unwrap();
    assert_eq!(runs.lines().count(), 1, "并发重入仅执行一次");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn denied_approval_returns_403_and_logs_denied() {
    let dir = temp_dir("denied");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state.approval.resolve(&event_id, "", false).await;
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert!(!dir.join("command-work").join("counter.log").exists());

    let page = state.command().log.query(Default::default()).await.unwrap();
    assert_eq!(page.items[0]["approval_status"], "denied");
    assert_eq!(page.items[0]["exec_status"], "not_run");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn accept_always_persists_and_skips_approval() {
    let dir = temp_dir("always");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state
        .approval
        .resolve_with_always(&event_id, "", true, true)
        .await;
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(dir.join("command_grants.json").exists());

    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("web"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202, "未授权 host 仍需审批");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_commands_requires_auth_and_clamps_limit() {
    let dir = temp_dir("admin");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let no_auth = client
        .get(format!("{base}/_admin/commands"))
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status().as_u16(), 401);

    client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    let body: Value = client
        .get(format!("{base}/_admin/commands?limit=500"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["limit"], 200);
    assert_eq!(body["total"], 1);

    let events: Value = client
        .get(format!("{base}/_admin/events?kind=command"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        events["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "command"),
        "SSE 事件环须含 command 事件: {events}"
    );

    let mut last = 0;
    for _ in 0..12 {
        last = client
            .get(format!("{base}/_admin/commands"))
            .header("X-Admin-Token", ADMIN_TOKEN)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429, "管理面通用限流须生效");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn failing_command_is_recorded_as_failed() {
    let dir = temp_dir("failed");
    let (app, state) = app(&dir, command_config(&dir, FAIL_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["exit_code"], 3);
    let page = state.command().log.query(Default::default()).await.unwrap();
    assert_eq!(page.items[0]["exec_status"], "failed");
    assert_eq!(page.items[0]["exit_code"], 3);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn ticket_removed_reentry_records_timeout() {
    let dir = temp_dir("timeout");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state.approval.remove(&event_id).await;

    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert!(!dir.join("command-work").join("counter.log").exists());

    let page = state.command().log.query(Default::default()).await.unwrap();
    assert_eq!(page.items[0]["approval_status"], "timeout");
    assert_eq!(page.items[0]["exec_status"], "not_run");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn pending_reentry_keeps_returning_202() {
    let dir = temp_dir("pending-reentry");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let first = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 202);
    let first_body: Value = first.json().await.unwrap();
    let event_id = first_body["approval_event_id"]
        .as_str()
        .expect("202 须返回审批 event id")
        .to_string();

    // 审批尚未落定：重入必须继续 202，不得被当作超时。
    for _ in 0..3 {
        let resp = client
            .post(format!("{base}/commands/run/invoke"))
            .headers(auth_headers("hash-ci"))
            .json(&invoke_body("api"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 202, "待审重入须保持 202");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["approval_event_id"], event_id, "同一审批复用同一单");
    }
    assert_eq!(
        state.approval.pending_event_ids().await.len(),
        1,
        "不得重复建单"
    );
    assert!(!dir.join("command-work").join("counter.log").exists());
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn static_auto_approve_rule_skips_approval() {
    let dir = temp_dir("static-auto");
    let (app, state) = app(&dir, config_with_auto_approve(&dir, COUNTER_SCRIPT));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "静态 auto_approve 须直接执行");
    assert!(state.approval.pending_event_ids().await.is_empty());
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn approved_then_failed_is_recorded_separately() {
    let dir = temp_dir("approved-failed");
    let (app, state) = app(&dir, command_config(&dir, FAIL_SCRIPT, true));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state.approval.resolve(&event_id, "", true).await;
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["host"], "api");
    let page = state.command().log.query(Default::default()).await.unwrap();
    assert_eq!(page.items[0]["approval_status"], "approved");
    assert_eq!(page.items[0]["exec_status"], "failed");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn invoke_without_deploy_secret_returns_403() {
    let dir = temp_dir("post-nosecret");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .header("x-caller-hash", "hash-ci")
        .header("x-caller-path", "/opt/ci/agent.sh")
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unbound_caller_invoke_returns_403() {
    let dir = temp_dir("post-unbound");
    let (app, state) = app(&dir, command_config(&dir, COUNTER_SCRIPT, false));
    enroll(&state, "/opt/other/agent.sh", "hash-other").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let mut headers = auth_headers("hash-other");
    headers.insert("x-caller-path", "/opt/other/agent.sh".parse().unwrap());
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(headers)
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn catalog_excludes_commands_outside_allow_list() {
    let dir = temp_dir("catalog-exclude");
    let mut cfg = command_config(&dir, COUNTER_SCRIPT, false);
    let program = cfg.commands.get("run").unwrap().program.clone();
    cfg.commands.insert(
        "hidden".to_string(),
        veil::config::CommandDef {
            program,
            args: Vec::new(),
            usage: "hidden".to_string(),
            description: String::new(),
            hosts: vec!["api".to_string()],
            timeout_secs: 10,
            requires_approval: false,
            parameters: Default::default(),
        },
    );
    let (app, state) = app(&dir, cfg);
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let body: Value = client
        .get(format!("{base}/commands"))
        .headers(auth_headers("hash-ci"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = body["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert_eq!(ids, vec!["run"], "目录不得包含 allow_commands 之外的命令");
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn accept_always_survives_restart() {
    let dir = temp_dir("always-restart");
    let cfg = command_config(&dir, COUNTER_SCRIPT, true);
    let (router, state) = app(&dir, cfg.clone());
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(router).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    let event_id = state
        .approval
        .pending_event_ids()
        .await
        .into_iter()
        .next()
        .expect("须建审批单");
    state
        .approval
        .resolve_with_always(&event_id, "", true, true)
        .await;
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    handle.abort();

    // 同一数据目录重建状态：运行时授权须从磁盘加载。
    let (router2, state2) = app(&dir, cfg);
    enroll(&state2, "/opt/ci/agent.sh", "hash-ci").await;
    let (base2, handle2) = serve(router2).await;
    let resp = client
        .post(format!("{base2}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "重启后 accept-always 须仍生效");
    assert!(state2.approval.pending_event_ids().await.is_empty());
    handle2.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_commands_disabled_returns_empty_page() {
    let dir = temp_dir("admin-disabled");
    let (app, _state) = app(&dir, disabled_config());
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/commands"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["total"], 0);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(
        !dir.join("commands.sqlite").exists(),
        "未启用的命令面不得创建日志库"
    );
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn exec_error_returns_503_without_leaking_the_program_path() {
    let dir = temp_dir("exec-error");
    let cfg = command_config(&dir, COUNTER_SCRIPT, false);
    let program = cfg.commands["run"].program.clone();
    let (app, state) = app(&dir, cfg);
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    // 启动校验通过后程序被移除：执行期 spawn 失败按不可用（503）返回。
    std::fs::remove_file(&program).unwrap();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 503);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains(&program.display().to_string()),
        "错误消息不得泄漏 program 路径: {body}"
    );
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn string_param_cannot_start_with_dash() {
    let dir = temp_dir("dash-param");
    let mut cfg = command_config(&dir, COUNTER_SCRIPT, false);
    if let Some(def) = cfg.commands.get_mut("run") {
        def.parameters.insert(
            "target".to_string(),
            veil::config::ParameterDef {
                kind: veil::config::ParameterKind::String,
            },
        );
        def.args = vec!["--target".to_string(), "{target}".to_string()];
    }
    let (app, state) = app(&dir, cfg);
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&json!({"target": {"host": "api"}, "params": {"target": "--evil"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn requires_approval_defaults_to_true() {
    let dir = temp_dir("default-approval");
    let (router, state) = app(&dir, config_without_requires_approval(&dir, COUNTER_SCRIPT));
    enroll(&state, "/opt/ci/agent.sh", "hash-ci").await;
    let (base, handle) = serve(router).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/commands/run/invoke"))
        .headers(auth_headers("hash-ci"))
        .json(&invoke_body("api"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202, "缺省须进入审批");
    assert!(!dir.join("command-work").join("counter.log").exists());
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}
