//! 真实进程 SIGHUP：信号既不得终止服务，也必须实际触发一次重载。
#![cfg(unix)]

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).ok(); }
}

struct ChildGuard(Child);

impl ChildGuard {
    fn id(&self) -> u32 { self.0.id() }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unique_dir() -> TempDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir =
        std::env::temp_dir().join(format!("veil-reload-signal-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

fn write_config(dir: &Path, port: u16) -> PathBuf {
    let config = dir.join("veil.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten_addr = \"127.0.0.1:{port}\"\n\n[storage]\ndata_dir = \"{}\"\n\n[credential]\nvault_backend = \"mock\"\n",
            dir.display()
        ),
    )
    .unwrap();
    config
}

fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn wait_ready(base: &str, client: &reqwest::Client) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(format!("{base}/health")).send().await
            && resp.status().is_success()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn spawn_ready(dir: &Path, client: &reqwest::Client) -> (ChildGuard, String, PathBuf) {
    for attempt in 0..3 {
        let port = pick_port();
        let config = write_config(dir, port);
        let log_path = dir.join(format!("veil-{attempt}.log"));
        let stderr = std::fs::File::create(&log_path).expect("创建进程日志");
        let child = ChildGuard(
            Command::new(env!("CARGO_BIN_EXE_veil"))
                .env_clear()
                .env("VEIL_CONFIG_FILE", &config)
                .env("VEIL_ALLOW_MOCK_TPM", "1")
                .env("OBSERVABILITY_ADMIN_TOKEN", ADMIN_TOKEN)
                .env("RUST_LOG", "veil=info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(stderr))
                .spawn()
                .expect("启动 veil 二进制"),
        );
        let base = format!("http://127.0.0.1:{port}");
        if wait_ready(&base, client).await {
            return (child, base, log_path);
        }
        drop(child);
    }
    panic!("veil 进程在 3 次端口尝试内未就绪");
}

#[tokio::test]
async fn sighup_triggers_reload_and_service_stays_healthy() {
    let dir = unique_dir();
    let client = reqwest::Client::new();
    let (child, base, log_path) = spawn_ready(&dir.0, &client).await;

    let status = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .expect("发送 SIGHUP");
    assert!(status.success(), "kill -HUP 须成功");

    let mut log = String::new();
    for _ in 0..100 {
        log = std::fs::read_to_string(&log_path).unwrap_or_default();
        if log.contains("KeePass 重载成功") && log.contains("signal") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        log.contains("KeePass 重载成功") && log.contains("signal"),
        "SIGHUP 须实际触发一次重载，日志: {log}"
    );

    let health = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("SIGHUP 后服务须仍可访问");
    assert_eq!(health.status().as_u16(), 200, "SIGHUP 不得终止进程");
    let reload = client
        .post(format!("{base}/reload"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(reload.status().as_u16(), 200, "信号后 HTTP 重载仍须可用");
}
