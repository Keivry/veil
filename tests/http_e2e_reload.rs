//! `POST /reload` 端到端：真实 KDBX + Mock TPM，验证换快照与 token 作废。

use {
    std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::Arc,
    },
    veil::{
        config::Config,
        keepass::{RealKeePass, tpm_password_provider_with_cache},
        router::build_router,
        state::{AppState, SqliteOutcome},
    },
};

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";
const MOCK_TPM_PASSWORD: &[u8] = b"veil-dev-mock-tpm-seal";

fn unique_dir() -> TempDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("veil-reload-e2e-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

struct TempDir(PathBuf);

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path { &self.0 }
}

impl Drop for TempDir {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).ok(); }
}

fn write_kdbx(path: &Path, secret: &str) {
    use keepass::{
        Database,
        DatabaseKey,
        db::fields::{PASSWORD, TITLE, USERNAME},
    };
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(TITLE, "网易");
        entry.set_unprotected(USERNAME, "u");
        entry.set_protected(PASSWORD, secret);
    }
    let key = DatabaseKey::new().with_password(&String::from_utf8_lossy(MOCK_TPM_PASSWORD));
    let mut bytes = Vec::new();
    db.save(&mut bytes, key).expect("测试 kdbx 须可保存");
    std::fs::write(path, bytes).expect("测试 kdbx 须可落盘");
}

fn test_state(dir: &Path) -> AppState {
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN.to_string(),
        ),
        ("DB_DIR".to_string(), dir.display().to_string()),
        ("TPM_DIR".to_string(), dir.display().to_string()),
    ]);
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("metrics.sqlite"),
        },
    );
    let (provider, cache) = tpm_password_provider_with_cache(dir.to_path_buf(), true);
    let backend = RealKeePass::new(dir.join("vault.kdbx"), None, provider)
        .with_db_dir(dir.to_path_buf())
        .with_master_password_cache(cache);
    state.with_keepass(Arc::new(backend))
}

async fn serve(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn reload_replaces_snapshot_and_invalidates_tokens_over_http() {
    let dir = unique_dir();
    let db_path = dir.join("vault.kdbx");
    write_kdbx(&db_path, "old-secret-1234");
    let state = test_state(&dir);
    let old_token = state.vault.register("old-secret-1234").unwrap();
    let (base, handle) = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base}/reload"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 200);
    let body: serde_json::Value = first.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["tokens_invalidated"], 1);
    assert!(
        body["db_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("vault.kdbx"))
    );
    assert!(state.vault.is_empty(), "重载成功须作废全部 token");
    assert_eq!(
        state.vault.restore_one(&old_token),
        None,
        "旧 token 不得再还原旧明文"
    );

    let entry = state.keepass.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(entry.password, "old-secret-1234");

    write_kdbx(&db_path, "new-secret-5678");
    let second = client
        .post(format!("{base}/reload"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 200);
    let entry = state.keepass.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(entry.password, "new-secret-5678", "重载后须读到新库值");

    let new_token = state.vault.register("old-secret-1234").unwrap();
    assert_ne!(new_token, old_token, "重载后同明文须分配新编号 token");

    handle.abort();
}

#[tokio::test]
async fn reload_conflicts_when_multiple_kdbx_exist() {
    let dir = unique_dir();
    write_kdbx(&dir.join("vault.kdbx"), "old-secret-1234");
    write_kdbx(&dir.join("backup.kdbx"), "old-secret-1234");
    let state = test_state(&dir);
    state.vault.register("old-secret-1234").unwrap();
    let (base, handle) = serve(state.clone()).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/reload"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_CONFLICT");
    assert!(!state.vault.is_empty(), "失败重载不得清空 token 映射");
    handle.abort();
}

#[tokio::test]
async fn reload_returns_503_without_kdbx_and_keeps_tokens() {
    let dir = unique_dir();
    let state = test_state(&dir);
    state.vault.register("old-secret-1234").unwrap();
    let (base, handle) = serve(state.clone()).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/reload"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_UNAVAILABLE");
    assert!(!state.vault.is_empty(), "失败重载不得清空 token 映射");
    handle.abort();
}

#[tokio::test]
async fn reload_returns_500_on_corrupt_kdbx_and_keeps_tokens() {
    let dir = unique_dir();
    std::fs::write(dir.join("vault.kdbx"), b"not a kdbx").unwrap();
    let state = test_state(&dir);
    state.vault.register("old-secret-1234").unwrap();
    let (base, handle) = serve(state.clone()).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/reload"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 500);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_KEEPASS");
    assert!(!state.vault.is_empty(), "失败重载不得清空 token 映射");
    handle.abort();
}
