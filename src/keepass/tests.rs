use super::*;

#[test]
fn locked_backend_returns_503() {
    let backend = MockKeePass::locked();
    let err = backend.fetch_credential("c1").unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn unlocked_backend_serves_placeholder_payload() {
    let backend = MockKeePass::unlocked();
    assert!(backend.fetch_credential("c1").is_ok());
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "veil-keepass-test-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture_backend(dir: &std::path::Path) -> RealKeePass {
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"fixture-master-pw",
        &[
            (
                "网易",
                "mail-user",
                "mail-secret-001",
                "https://mail.example.com",
                vec![
                    ("授权码".to_string(), "authcode-abc-123".to_string(), true),
                    ("备注".to_string(), "plain-note".to_string(), false),
                ],
            ),
            ("备用", "backup-user", "backup-secret-002", "", vec![]),
        ],
    );
    let provider: PasswordProvider =
        std::sync::Arc::new(|| Ok(Zeroizing::new(b"fixture-master-pw".to_vec())));
    RealKeePass::new(db_path, None, provider)
}

#[tokio::test]
async fn real_fixture_full_entry_replay() {
    let dir = unique_temp_dir("full");
    let backend = fixture_backend(&dir);
    assert!(backend.is_unlocked());
    let snapshot = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(snapshot.title, "网易");
    assert_eq!(snapshot.username, "mail-user");
    assert_eq!(snapshot.password, "mail-secret-001");
    assert_eq!(snapshot.url, "https://mail.example.com");
    let authcode = snapshot.custom_value("授权码").expect("自定义字段须存在");
    assert_eq!(authcode.value, "authcode-abc-123");
    assert!(authcode.protected);
    let note = snapshot.custom_value("备注").expect("明文字段须存在");
    assert!(!note.protected);
    assert_eq!(backend.open_count(), 1);
    let _ = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(backend.open_count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn missing_entry_returns_named_404() {
    let dir = unique_temp_dir("missing");
    let backend = fixture_backend(&dir);
    let err = backend.fetch_entry("不存在".to_string()).await.unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
    assert!(err.to_string().contains("不存在"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn missing_db_returns_503_without_unlock_attempt() {
    let dir = unique_temp_dir("nodb");
    let opened = std::sync::Arc::new(AtomicBool::new(false));
    let flag = opened.clone();
    let provider: PasswordProvider = std::sync::Arc::new(move || {
        flag.store(true, Ordering::SeqCst);
        Ok(Zeroizing::new(b"pw".to_vec()))
    });
    let backend = RealKeePass::new(dir.join("absent.kdbx"), None, provider);
    assert!(!backend.is_unlocked());
    let err = backend.fetch_entry("网易".to_string()).await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!opened.load(Ordering::SeqCst));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn wrong_master_password_returns_500() {
    let dir = unique_temp_dir("badpw");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"correct-pw", &[("网易", "u", "s", "", vec![])]);
    let provider: PasswordProvider =
        std::sync::Arc::new(|| Ok(Zeroizing::new(b"wrong-pw".to_vec())));
    let backend = RealKeePass::new(db_path, None, provider);
    let err = backend.fetch_entry("网易".to_string()).await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn concurrent_cold_cache_opens_once() {
    let dir = unique_temp_dir("race");
    let backend = std::sync::Arc::new(fixture_backend(&dir));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let backend = backend.clone();
        handles.push(tokio::spawn(async move {
            backend.fetch_entry("备用".to_string()).await.unwrap()
        }));
    }
    for handle in handles {
        let snapshot = handle.await.unwrap();
        assert_eq!(snapshot.password, "backup-secret-002");
    }
    assert_eq!(backend.open_count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn cache_clear_reopens() {
    let dir = unique_temp_dir("invalidate");
    let backend = fixture_backend(&dir);
    backend.fetch_entry("备用".to_string()).await.unwrap();
    assert_eq!(backend.open_count(), 1);
    backend.clear_cache();
    backend.fetch_entry("备用".to_string()).await.unwrap();
    assert_eq!(backend.open_count(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tpm_password_provider_reuses_cache() {
    let dir = unique_temp_dir("tpm-cache");
    let provider = tpm_password_provider(dir.clone(), true);
    let first = provider().expect("mock 放行须解封成功");
    assert!(first.len() >= 4);
    let second = provider().expect("二次调用须复用缓存");
    assert_eq!(first.as_slice(), second.as_slice());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unlock_after_lock_rederives_via_tpm() {
    // `lock` 清除缓存后再次取用须重新经 TPM 解封，值一致（mock seal 确定性）。
    let dir = unique_temp_dir("tpm-reunlock");
    let (provider, cache) = tpm_password_provider_with_cache(dir.clone(), true);
    let first = provider().expect("首次 TPM 解封须成功");
    assert!(cache.has_cached(), "解封后须有缓存");
    assert!(cache.clear(), "lock 清除须报告原缓存存在");
    assert!(!cache.has_cached(), "清除后缓存须为空");
    let second = provider().expect("清除后须重新经 TPM 解封");
    assert!(cache.has_cached(), "重新解封后缓存须回填");
    assert_eq!(first.as_slice(), second.as_slice(), "同一 seal 解封值稳定");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn duplicate_titles_return_first_without_sorting() {
    let dir = unique_temp_dir("first");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"pw",
        &[
            ("同名", "zeta-user", "first-secret", "", vec![]),
            ("同名", "alpha-user", "second-secret", "", vec![]),
        ],
    );
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(db_path, None, provider);
    let snapshot = backend.fetch_entry("同名".to_string()).await.unwrap();
    assert_eq!(snapshot.username, "zeta-user");
    assert_eq!(snapshot.password, "first-secret");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unlock_quickcheck_keys_off_file_presence_only() {
    let dir = unique_temp_dir("probe");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "s", "", vec![])]);
    let ok_provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let ok = RealKeePass::new(db_path.clone(), None, ok_provider);
    assert!(ok.is_unlocked());
    // 快检不触提供器：空口令提供器同样视为库文件就绪（解锁承诺由取用路径承担）。
    let empty_provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(Vec::new())));
    let empty = RealKeePass::new(db_path, None, empty_provider);
    assert!(empty.is_unlocked());
    let absent = RealKeePass::new(
        dir.join("absent.kdbx"),
        None,
        std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec()))),
    );
    assert!(!absent.is_unlocked());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn second_lookup_does_not_reunlock_password() {
    let dir = unique_temp_dir("tpm-reuse");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"fixture-master-pw",
        &[("网易", "u", "s", "", vec![])],
    );
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let provider: PasswordProvider = std::sync::Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(b"fixture-master-pw".to_vec()))
    });
    let backend = RealKeePass::new(db_path, None, provider);
    backend.fetch_entry("网易".to_string()).await.unwrap();
    backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(backend.open_count(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unlock_chain_tpm_unseal_failure_no_fallback() {
    // TPM 解封失败（无 seal 文件）→ 解锁失败 500，不回落软件明文。
    let dir = unique_temp_dir("chain-a");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"any-master", &[("网易", "u", "s", "", vec![])]);
    let (provider, _cache) = tpm_password_provider_with_cache(dir.clone(), false);
    assert!(provider().is_err(), "无 seal 文件须解封失败");
    let backend = RealKeePass::new(db_path, None, provider);
    let err = backend.fetch_entry("网易".to_string()).await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(
        err.to_string().contains("主密码派生失败"),
        "须报主密码派生失败而非放行: {err}"
    );
    assert!(!backend.is_cached(), "解封失败不得缓存库");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unlock_chain_wrong_master_password_returns_500() {
    // TPM 解封成功但主密码与库不匹配 → 500，不误判成功。
    let dir = unique_temp_dir("chain-b");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"not-the-mock-seal",
        &[("网易", "u", "s", "", vec![])],
    );
    let (provider, _cache) = tpm_password_provider_with_cache(dir.clone(), true);
    let backend = RealKeePass::new(db_path, None, provider);
    let err = backend.fetch_entry("网易".to_string()).await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!backend.is_cached(), "解密失败不得缓存半开库");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unlock_chain_concurrent_cold_single_unseal() {
    // 并发冷启动经 tpm_password_provider 单开——provider 只解封一次。
    let dir = unique_temp_dir("chain-c");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"veil-dev-mock-tpm-seal",
        &[("网易", "u", "s", "", vec![])],
    );
    let (tpm_provider, cache) = tpm_password_provider_with_cache(dir.clone(), true);
    let unseals = std::sync::Arc::new(AtomicUsize::new(0));
    let counting: PasswordProvider = {
        let inner = tpm_provider.clone();
        let counter = unseals.clone();
        std::sync::Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            inner()
        })
    };
    let backend = std::sync::Arc::new(
        RealKeePass::new(db_path, None, counting).with_master_password_cache(cache),
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let backend = backend.clone();
        handles.push(tokio::spawn(async move {
            backend.fetch_entry("网易".to_string()).await.unwrap()
        }));
    }
    for handle in handles {
        assert_eq!(handle.await.unwrap().password, "s");
    }
    assert_eq!(unseals.load(Ordering::SeqCst), 1, "并发冷启动须只解封一次");
    assert_eq!(backend.open_count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unlock_chain_lock_clears_cache_and_reunseals() {
    // `lock` 清库缓存 + 主密码缓存后，取用须重新经 TPM 解封（缓存已清零）。
    let dir = unique_temp_dir("chain-d");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"veil-dev-mock-tpm-seal",
        &[("网易", "u", "s", "", vec![])],
    );
    let (provider, cache) = tpm_password_provider_with_cache(dir.clone(), true);
    let backend =
        RealKeePass::new(db_path, None, provider).with_master_password_cache(cache.clone());
    backend.fetch_entry("网易".to_string()).await.unwrap();
    assert!(cache.has_cached(), "解封后主密码须缓存");
    backend.clear_cache();
    assert!(
        backend.clear_master_password(),
        "lock 须清除并报告原缓存存在"
    );
    assert!(!cache.has_cached(), "lock 后主密码缓存须清零");
    backend.fetch_entry("网易".to_string()).await.unwrap();
    assert!(cache.has_cached(), "重解锁须重新解封回填缓存");
    assert_eq!(backend.open_count(), 2, "lock 后须重开库");
    std::fs::remove_dir_all(&dir).ok();
}
