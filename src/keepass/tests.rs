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

#[tokio::test]
async fn mock_reload_is_noop_success() {
    let backend = MockKeePass::unlocked();
    assert_eq!(backend.reload().await.unwrap(), None);
}

#[tokio::test]
async fn reload_redecrypts_cached_snapshot() {
    let dir = unique_temp_dir("reload-decrypt");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "old-secret", "", vec![])]);
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(db_path.clone(), None, provider);
    let first = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(first.password, "old-secret");
    assert_eq!(backend.open_count(), 1);
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "new-secret", "", vec![])]);
    let outcome = backend
        .reload()
        .await
        .unwrap()
        .expect("真实后端须返回重载结果");
    assert_eq!(
        outcome,
        ReloadOutcome {
            db_path: db_path.clone(),
            open_count: 2,
        }
    );
    let second = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(second.password, "new-secret");
    assert_eq!(backend.open_count(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_failure_keeps_old_snapshot() {
    let dir = unique_temp_dir("reload-fail");
    let backend = fixture_backend(&dir);
    let before = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(before.password, "mail-secret-001");
    assert_eq!(backend.open_count(), 1);
    std::fs::write(dir.join("vault.kdbx"), b"not-a-kdbx").unwrap();
    let err = backend.reload().await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(matches!(err, VeilError::KeePass { .. }));
    let after = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(after.password, "mail-secret-001");
    assert!(backend.is_cached(), "失败重载不得清空旧快照");
    assert_eq!(backend.open_count(), 1);
    build_test_kdbx(
        &dir.join("vault.kdbx"),
        b"fixture-master-pw",
        &[("网易", "u", "recovered", "", vec![])],
    );
    let recovered = backend
        .reload()
        .await
        .unwrap()
        .expect("500 失败后单飞标志须复位");
    assert_eq!(recovered.open_count, 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_uses_new_master_password() {
    let dir = unique_temp_dir("reload-newpw");
    let db_path = dir.join("vault.kdbx");
    let password = std::sync::Arc::new(Mutex::new(b"pw-old".to_vec()));
    let provider: PasswordProvider = {
        let password = password.clone();
        std::sync::Arc::new(move || {
            let pw = password.lock().expect("测试口令锁").clone();
            Ok(Zeroizing::new(pw))
        })
    };
    build_test_kdbx(
        &db_path,
        b"pw-old",
        &[("网易", "u", "old-secret", "", vec![])],
    );
    let backend = RealKeePass::new(db_path.clone(), None, provider);
    let first = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(first.password, "old-secret");
    build_test_kdbx(
        &db_path,
        b"pw-new",
        &[("网易", "u", "new-secret", "", vec![])],
    );
    *password.lock().expect("测试口令锁") = b"pw-new".to_vec();
    let outcome = backend.reload().await.unwrap().expect("换密后重载须成功");
    assert_eq!(outcome.open_count, 2);
    let second = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(second.password, "new-secret");
    std::fs::remove_dir_all(&dir).ok();
}

fn blocking_provider() -> (
    PasswordProvider,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let provider: PasswordProvider = std::sync::Arc::new(move || {
        let _ = started_tx.send(());
        let _ = release_rx.lock().map(|rx| rx.recv());
        Ok(Zeroizing::new(b"pw".to_vec()))
    });
    (provider, started_rx, release_tx)
}

async fn await_provider_entered(started: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || {
        started
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("provider 须在限时内被调用")
    })
    .await
    .expect("等待 provider 的任务须完成");
}

#[tokio::test]
async fn concurrent_reload_conflicts_without_queueing() {
    let dir = unique_temp_dir("reload-inflight");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "s", "", vec![])]);
    let (provider, started, release) = blocking_provider();
    let backend = std::sync::Arc::new(RealKeePass::new(db_path, None, provider));
    let first = {
        let backend = backend.clone();
        tokio::spawn(async move { backend.reload().await })
    };
    await_provider_entered(started).await;
    let err = tokio::time::timeout(std::time::Duration::from_secs(2), backend.reload())
        .await
        .expect("并发重载须立即返回而非排队")
        .unwrap_err();
    assert!(matches!(err, VeilError::Conflict { .. }));
    release.send(()).expect("释放 provider");
    drop(release);
    let first_outcome = first
        .await
        .expect("首个重载须完成")
        .unwrap()
        .expect("须有重载结果");
    assert_eq!(first_outcome.open_count, 1);
    let next = backend.reload().await.unwrap().expect("单飞标志须复位");
    assert_eq!(next.open_count, 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_aborts_when_lock_races_decrypt() {
    let dir = unique_temp_dir("reload-lock-race");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "s", "", vec![])]);
    let (provider, started, release) = blocking_provider();
    let backend = std::sync::Arc::new(RealKeePass::new(db_path, None, provider));
    let handle = {
        let backend = backend.clone();
        tokio::spawn(async move { backend.reload().await })
    };
    await_provider_entered(started).await;
    backend.clear_cache();
    release.send(()).expect("释放 provider");
    let err = handle.await.expect("重载任务须完成").unwrap_err();
    assert!(matches!(err, VeilError::Conflict { .. }));
    assert!(err.to_string().contains("lock"));
    assert!(!backend.is_cached(), "lock 竞争后不得复活快照");
    assert_eq!(backend.open_count(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn lock_during_cold_fetch_aborts_writeback() {
    let dir = unique_temp_dir("fetch-lock-race");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "s", "", vec![])]);
    let (provider, started, release) = blocking_provider();
    let backend = std::sync::Arc::new(RealKeePass::new(db_path, None, provider));
    let handle = {
        let backend = backend.clone();
        tokio::spawn(async move { backend.fetch_entry("网易".to_string()).await })
    };
    await_provider_entered(started).await;
    backend.clear_cache();
    release.send(()).expect("释放 provider");
    let err = handle.await.expect("取用任务须完成").unwrap_err();
    assert!(matches!(err, VeilError::Unavailable { .. }));
    assert!(err.to_string().contains("KeePass 已锁定"));
    assert!(!backend.is_cached(), "lock 竞争后不得回填快照");
    assert_eq!(backend.open_count(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_empty_dir_unavailable() {
    let dir = unique_temp_dir("reload-empty-dir");
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(dir.join("veil.kdbx"), None, provider);
    let err = backend.reload().await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(err.to_string().contains("密码库未配置"));
    assert_eq!(backend.open_count(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_ambiguous_dir_conflict() {
    let dir = unique_temp_dir("reload-ambiguous");
    std::fs::write(dir.join("a.kdbx"), b"a").unwrap();
    std::fs::write(dir.join("z.kdbx"), b"z").unwrap();
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(dir.join("a.kdbx"), None, provider);
    let err = backend.reload().await.unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
    let message = err.to_string();
    assert!(matches!(err, VeilError::Conflict { .. }));
    assert!(
        message.contains("a.kdbx") && message.contains("z.kdbx"),
        "冲突信息须指名全部候选: {message}"
    );
    assert_eq!(backend.open_count(), 0, "多库不得触发解密");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_single_db_with_keyfile_succeeds() {
    let dir = unique_temp_dir("reload-keyfile");
    let db_path = dir.join("vault.kdbx");
    let keyfile = dir.join("vault.key");
    let key_bytes = b"bare-test-keyfile-material";
    build_test_kdbx_with_keyfile(
        &db_path,
        b"pw",
        key_bytes,
        &[("网易", "u", "key-secret", "", vec![])],
    );
    std::fs::write(&keyfile, key_bytes).unwrap();
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(db_path.clone(), None, provider);
    let outcome = backend
        .reload()
        .await
        .unwrap()
        .expect("单库带 keyfile 须重载成功");
    assert_eq!(outcome.db_path, db_path);
    let snapshot = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(snapshot.password, "key-secret");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn cached_fetch_survives_missing_file() {
    let dir = unique_temp_dir("cached-rename");
    let backend = fixture_backend(&dir);
    let first = backend.fetch_entry("备用".to_string()).await.unwrap();
    assert_eq!(first.password, "backup-secret-002");
    let db_path = dir.join("vault.kdbx");
    let moved = dir.join("vault.kdbx.bak");
    std::fs::rename(&db_path, &moved).unwrap();
    let cached = backend.fetch_entry("备用".to_string()).await.unwrap();
    assert_eq!(cached.password, "backup-secret-002");
    assert_eq!(backend.open_count(), 1);
    backend.clear_cache();
    let err = backend.fetch_entry("备用".to_string()).await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(err.to_string().contains("密码库未配置"));
    std::fs::rename(&moved, &db_path).ok();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_empty_database_then_fetch_not_found() {
    let dir = unique_temp_dir("reload-empty-db");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[]);
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(db_path, None, provider);
    let outcome = backend.reload().await.unwrap().expect("空库重载须成功");
    assert_eq!(outcome.open_count, 1);
    let err = backend
        .fetch_entry("任意条目".to_string())
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
    assert!(backend.is_cached(), "空库也须替换为已解密快照");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn clear_cache_advances_lock_epoch() {
    let dir = unique_temp_dir("lock-epoch");
    let backend = fixture_backend(&dir);
    let before = backend.lock_epoch.load(Ordering::SeqCst);
    backend.clear_cache();
    assert_eq!(backend.lock_epoch.load(Ordering::SeqCst), before + 1);
    backend.clear_cache();
    assert_eq!(backend.lock_epoch.load(Ordering::SeqCst), before + 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_provider_failure_keeps_old_snapshot() {
    let dir = unique_temp_dir("reload-provider-fail");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "old-secret", "", vec![])]);
    let fail = std::sync::Arc::new(AtomicBool::new(false));
    let provider: PasswordProvider = {
        let fail = fail.clone();
        std::sync::Arc::new(move || {
            if fail.load(Ordering::SeqCst) {
                anyhow::bail!("TPM 解封失败（测试）");
            }
            Ok(Zeroizing::new(b"pw".to_vec()))
        })
    };
    let backend = RealKeePass::new(db_path, None, provider);
    let first = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(first.password, "old-secret");
    fail.store(true, Ordering::SeqCst);
    let err = backend.reload().await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(matches!(err, VeilError::KeePass { .. }));
    let after = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(after.password, "old-secret", "解封失败不得影响旧快照");
    assert!(backend.is_cached());
    assert_eq!(backend.open_count(), 1, "失败重载不得推进打开计数");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_inflight_resets_after_failure() {
    let dir = unique_temp_dir("reload-inflight-reset");
    let db_path = dir.join("vault.kdbx");
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(db_path.clone(), None, provider);
    let err = backend.reload().await.unwrap_err();
    assert!(matches!(err, VeilError::Unavailable { .. }));
    build_test_kdbx(&db_path, b"pw", &[("网易", "u", "s", "", vec![])]);
    let ok = backend
        .reload()
        .await
        .unwrap()
        .expect("失败后单飞标志须复位");
    assert_eq!(ok.open_count, 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_switches_to_renamed_single_database() {
    let dir = unique_temp_dir("reload-rename");
    let old = dir.join("a.kdbx");
    build_test_kdbx(&old, b"pw", &[("网易", "u", "old-secret", "", vec![])]);
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(old.clone(), None, provider);
    let first = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(first.password, "old-secret");
    std::fs::rename(&old, dir.join("a.kdbx.bak")).unwrap();
    let new = dir.join("b.kdbx");
    build_test_kdbx(&new, b"pw", &[("网易", "u", "new-secret", "", vec![])]);
    let outcome = backend.reload().await.unwrap().expect("换名单库须成功");
    assert_eq!(outcome.db_path, new);
    let after = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(after.password, "new-secret");
    assert_eq!(
        backend
            .fetch_entry("备用".to_string())
            .await
            .unwrap_err()
            .status_code(),
        axum::http::StatusCode::NOT_FOUND,
        "换名后旧条目不得残留"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_rereads_updated_keyfile() {
    let dir = unique_temp_dir("reload-keyfile-update");
    let db_path = dir.join("vault.kdbx");
    let key_path = dir.join("vault.key");
    build_test_kdbx_with_keyfile(
        &db_path,
        b"pw",
        b"key-one",
        &[("网易", "u", "old-secret", "", vec![])],
    );
    std::fs::write(&key_path, b"key-one").unwrap();
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(db_path.clone(), Some(key_path.clone()), provider);
    let first = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(first.password, "old-secret");
    build_test_kdbx_with_keyfile(
        &db_path,
        b"pw",
        b"key-two",
        &[("网易", "u", "new-secret", "", vec![])],
    );
    std::fs::write(&key_path, b"key-two").unwrap();
    backend
        .reload()
        .await
        .unwrap()
        .expect("更新 keyfile 后须成功");
    let after = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(
        after.password, "new-secret",
        "重载须重新读取磁盘上的 keyfile"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_clears_stale_master_password_and_uses_new_secret() {
    let dir = unique_temp_dir("reload-clear-pwcache");
    let db_path = dir.join("vault.kdbx");
    build_test_kdbx(
        &db_path,
        b"new-pw",
        &[("网易", "u", "new-secret", "", vec![])],
    );
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"new-pw".to_vec())));
    let cache = MasterPasswordCache::default();
    cache.seed(b"old-pw".to_vec());
    let backend = RealKeePass::new(db_path, None, provider).with_master_password_cache(cache);
    assert!(backend.master_password_cached(), "前置：缓存须有旧派生值");
    let outcome = backend.reload().await.unwrap().expect("按新密码须成功");
    assert_eq!(outcome.open_count, 1);
    assert!(
        !backend.master_password_cached(),
        "重载须清除旧派生值，不得沿用缓存"
    );
    let snapshot = backend.fetch_entry("网易".to_string()).await.unwrap();
    assert_eq!(snapshot.password, "new-secret");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn reload_unreadable_directory_maps_to_keepass_500() {
    let dir = unique_temp_dir("reload-dir-io");
    let not_a_dir = dir.join("not-a-dir");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let provider: PasswordProvider = std::sync::Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let backend = RealKeePass::new(dir.join("vault.kdbx"), None, provider).with_db_dir(not_a_dir);
    let err = backend.reload().await.unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(matches!(err, VeilError::KeePass { .. }));
    std::fs::remove_dir_all(&dir).ok();
}
