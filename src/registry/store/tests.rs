use super::*;

#[test]
fn duplicate_path_conflicts_409_same_hash_multi_path_allowed() {
    let mut reg = CallerRegistry::empty();
    reg.register("/s/a.sh", "h1").unwrap();
    let err = reg.register("/s/a.sh", "h2").unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
    // 同 hash 不同 path：允许分别注册（冲突只看 path）。
    let e2 = reg.register("/s/b.sh", "h1").unwrap();
    assert_eq!(e2.caller_path, "/s/b.sh");
    assert_eq!(reg.len(), 2);
}

#[test]
fn revoked_caller_path_can_reregister() {
    // AUTH-7：已吊销 `caller_path` 允许重注册，新条目全新初始化。
    let mut reg = CallerRegistry::empty();
    reg.register_extended(&RegisterParams {
        caller_path: "/s/rev-reuse.sh".to_string(),
        caller_hash: "h-old".to_string(),
        ..RegisterParams::default()
    })
    .unwrap();
    reg.set_enabled("/s/rev-reuse.sh", true).unwrap();
    reg.revoke("/s/rev-reuse.sh").unwrap();
    let e = reg
        .register_extended(&RegisterParams {
            caller_path: "/s/rev-reuse.sh".to_string(),
            caller_hash: "h-new".to_string(),
            ..RegisterParams::default()
        })
        .expect("已吊销路径须可复用重注册");
    assert_eq!(e.expected_hash, "h-new");
    assert!(!e.enabled && !e.revoked, "重注册须全新初始化");
}

#[test]
fn reregister_clears_old_hash_grace() {
    // AUTH-7：重注册不得继承已吊销条目的旧哈希宽限。
    let mut reg = CallerRegistry::empty();
    reg.register_extended(&RegisterParams {
        caller_path: "/s/grace-reuse.sh".to_string(),
        caller_hash: "h1".to_string(),
        ..RegisterParams::default()
    })
    .unwrap();
    reg.approve_hash_change("/s/grace-reuse.sh", "h2").unwrap();
    assert!(
        reg.lookup_by_path("/s/grace-reuse.sh")
            .unwrap()
            .old_hash
            .is_some(),
        "前置：宽限须已写入"
    );
    reg.revoke("/s/grace-reuse.sh").unwrap();
    let e = reg
        .register_extended(&RegisterParams {
            caller_path: "/s/grace-reuse.sh".to_string(),
            caller_hash: "h3".to_string(),
            ..RegisterParams::default()
        })
        .unwrap();
    assert!(
        e.old_hash.is_none() && e.old_hash_expires_at.is_none(),
        "重注册条目不得继承旧哈希宽限"
    );
    assert!(!e.matches_old_hash("h2"));
}

#[test]
fn register_extended_rejects_duplicate_unrevoked_name() {
    let mut reg = CallerRegistry::empty();
    let p = |path: &str, name: &str| RegisterParams {
        caller_path: path.to_string(),
        caller_hash: format!("h-{path}"),
        name: name.to_string(),
        ..RegisterParams::default()
    };
    reg.register_extended(&p("/s/u1.sh", "uniq-job")).unwrap();
    let dup = reg.register_extended(&p("/s/u2.sh", "uniq-job"));
    assert!(
        matches!(dup, Err(VeilError::Conflict { .. })),
        "未吊销重名须 409"
    );
}

#[test]
fn new_registration_disabled_by_default() {
    let mut reg = CallerRegistry::empty();
    let e = reg.register("/s/a.sh", "h1").unwrap();
    assert!(!e.enabled && !e.revoked);
    assert_eq!(e.status_emoji(), "🔓");
}

#[test]
fn atomic_save_and_integrity_check() {
    let dir = std::env::temp_dir().join(format!(
        "veil-reg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("caller_registry.json");
    let mut reg = CallerRegistry::empty();
    reg.register("/s/a.sh", "h1").unwrap();
    reg.save_to(&path).unwrap();
    let loaded = CallerRegistry::load_from(&path).unwrap();
    assert_eq!(loaded.len(), 1);
    let mut raw = std::fs::read_to_string(&path).unwrap();
    raw = raw.replace('h', "x");
    std::fs::write(&path, raw).unwrap();
    assert!(CallerRegistry::load_from(&path).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn name_dedup_rejects_and_releases_on_revoke() {
    let mut reg = CallerRegistry::empty();
    let p = |path: &str, name: &str| RegisterParams {
        caller_path: path.to_string(),
        caller_hash: format!("h-{path}"),
        name: name.to_string(),
        ..RegisterParams::default()
    };
    reg.register_extended(&p("/s/n1.sh", "named-job")).unwrap();
    // 未吊销重名 → 409 Conflict。
    let dup = reg.register_extended(&p("/s/n2.sh", "named-job"));
    assert!(matches!(dup, Err(VeilError::Conflict { .. })), "重名须 409");
    // 按名定位命中未吊销条目。
    assert_eq!(
        reg.lookup_by_name("named-job")
            .map(|e| e.caller_path.clone()),
        Some("/s/n1.sh".to_string())
    );
    assert_eq!(reg.resolve_path("named-job").as_deref(), Some("/s/n1.sh"));
    // 吊销后释放名称，可复用。
    reg.revoke("/s/n1.sh").unwrap();
    reg.register_extended(&p("/s/n3.sh", "named-job")).unwrap();
    assert_eq!(
        reg.lookup_by_name("named-job")
            .map(|e| e.caller_path.clone()),
        Some("/s/n3.sh".to_string()),
        "未吊销优先于历史已吊销同名"
    );
}

#[test]
fn revoke_disables_entry() {
    let mut reg = CallerRegistry::empty();
    reg.register("/s/a.sh", "h1").unwrap();
    reg.set_enabled("/s/a.sh", true).unwrap();
    reg.revoke("/s/a.sh").unwrap();
    let e = reg.lookup_by_path("/s/a.sh").unwrap();
    assert!(e.revoked && !e.enabled);
    assert_eq!(e.status_emoji(), "❎");
}

#[test]
fn approve_hash_change_applies_and_enables() {
    let mut reg = CallerRegistry::empty();
    reg.register("/s/a.sh", "h1").unwrap();
    reg.approve_hash_change("/s/a.sh", "h2").unwrap();
    let e = reg.lookup_by_path("/s/a.sh").unwrap();
    assert_eq!(e.expected_hash, "h2");
    assert!(e.enabled && !e.revoked);
    assert_eq!(e.status_emoji(), "✅");
}

#[test]
fn hash_change_three_state() {
    let mut reg = CallerRegistry::empty();
    // 🔓 保持 allow_mode 不变，激活并写宽限。
    reg.register_extended(&RegisterParams {
        caller_path: "/s/keep.sh".to_string(),
        caller_hash: "keep-old".to_string(),
        ..RegisterParams::default()
    })
    .unwrap();
    reg.approve_hash_change_with_script_sha256(
        "/s/keep.sh",
        "keep-new",
        "sha-keep".to_string(),
        HashChangeOutcome::KeepAuto,
    )
    .unwrap();
    let e = reg.lookup_by_path("/s/keep.sh").unwrap();
    assert_eq!(e.allow_mode, None, "🔓 须保持 allow_mode 不变");
    assert!(e.enabled && !e.revoked);
    assert_eq!(e.old_hash.as_deref(), Some("keep-old"));
    assert!(e.old_hash_expires_at.is_some());
    assert_eq!(e.script_sha256, "sha-keep");
    // ✅ 降级人工（allow_mode = Pending），仍激活。
    reg.register_extended(&RegisterParams {
        caller_path: "/s/demote.sh".to_string(),
        caller_hash: "demote-old".to_string(),
        allow_mode: Some(crate::config::AutoApprove::Allow),
        ..RegisterParams::default()
    })
    .unwrap();
    reg.approve_hash_change_with_script_sha256(
        "/s/demote.sh",
        "demote-new",
        "sha-demote".to_string(),
        HashChangeOutcome::DemoteManual,
    )
    .unwrap();
    let e = reg.lookup_by_path("/s/demote.sh").unwrap();
    assert_eq!(
        e.allow_mode,
        Some(crate::config::AutoApprove::Pending),
        "✅ 须降级为人工审批模式"
    );
    assert!(e.enabled && !e.revoked);
    assert_eq!(e.expected_hash, "demote-new");
    // ❎ 禁用（fail-closed），仍写宽限与哈希。
    reg.register_extended(&RegisterParams {
        caller_path: "/s/disable.sh".to_string(),
        caller_hash: "disable-old".to_string(),
        ..RegisterParams::default()
    })
    .unwrap();
    reg.approve_hash_change_with_script_sha256(
        "/s/disable.sh",
        "disable-new",
        "sha-disable".to_string(),
        HashChangeOutcome::Disable,
    )
    .unwrap();
    let e = reg.lookup_by_path("/s/disable.sh").unwrap();
    assert!(!e.enabled, "❎ 须禁用条目");
    assert_eq!(e.expected_hash, "disable-new");
    assert_eq!(e.old_hash.as_deref(), Some("disable-old"));
    assert!(e.old_hash_expires_at.is_some());
}

#[test]
fn load_from_migrates_legacy() {
    let dir = std::env::temp_dir().join(format!(
        "veil-reg-legacy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("caller_registry.json");
    let old = serde_json::json!({
        "version": 1,
        "callers": [{
            "script_path": "/s/legacy.sh",
            "script_hash": "legacy-h1",
            "name": "legacy-job",
            "enabled": true,
            "allowed_entries": {"网易": ["授权码"]}
        }]
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&old).unwrap()).unwrap();
    let loaded = CallerRegistry::load_from(&path).unwrap();
    assert_eq!(loaded.len(), 1, "旧格式须加载期一次性迁移");
    let e = loaded.lookup_by_path("/s/legacy.sh").unwrap();
    assert_eq!(e.expected_hash, "legacy-h1");
    assert!(e.enabled);
    assert!(e.check_entry_allowed("网易", Some("授权码")));
    assert!(path.with_extension("json.bak").exists(), "须留 .bak 备份");
    // 写回后为新格式，可直接再加载且不重复迁移。
    let reloaded = CallerRegistry::load_from(&path).unwrap();
    assert_eq!(reloaded.len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn saved_file_permissions_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!(
        "veil-reg-0600-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("caller_registry.json");
    let mut reg = CallerRegistry::empty();
    reg.register("/s/a.sh", "h1").unwrap();
    reg.save_to(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn extended_register_keeps_name_desc_and_allowlist() {
    let mut reg = CallerRegistry::empty();
    reg.register_extended(&RegisterParams {
        caller_path: "/s/go.sh".to_string(),
        caller_hash: "gh1".to_string(),
        name: "check-mail".to_string(),
        description: "检查邮件".to_string(),
        entries: BTreeMap::from([("网易".to_string(), vec!["授权码".to_string()])]),
        allow_mode: Some(crate::config::AutoApprove::Pending),
    })
    .unwrap();
    let e = reg.lookup_by_path("/s/go.sh").unwrap();
    assert_eq!(e.name, "check-mail");
    assert_eq!(e.description, "检查邮件");
    assert_eq!(
        e.effective_allow_mode(crate::config::AutoApprove::Allow),
        crate::config::AutoApprove::Pending
    );
}

#[test]
fn missing_entry_no_db_invalid_json_and_double_revoke_idempotent() {
    let mut reg = CallerRegistry::empty();
    assert!(reg.lookup_by_path("/s/nope.sh").is_none(), "未注册缺条目");
    let err = reg.revoke("/s/nope.sh").unwrap_err();
    assert!(err.to_string().contains("调用方不存在"), "缺条目吊销须明错");
    reg.register("/s/d.sh", "h1").unwrap();
    reg.revoke("/s/d.sh").unwrap();
    reg.revoke("/s/d.sh").expect("清理双删须幂等成功");
    let e = reg.lookup_by_path("/s/d.sh").unwrap();
    assert!(e.revoked && !e.enabled);
    let missing = std::env::temp_dir().join(format!(
        "veil-reg-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let loaded = CallerRegistry::load_from(&missing.join("no.json")).unwrap();
    assert_eq!(loaded.len(), 0, "无库须兼容空表");
    std::fs::create_dir_all(&missing).unwrap();
    let bad = missing.join("bad.json");
    std::fs::write(&bad, b"{not json").unwrap();
    assert!(CallerRegistry::load_from(&bad).is_err(), "无效 JSON 须拒载");
    std::fs::remove_dir_all(&missing).ok();
}

#[test]
fn integrity_serialize_failure() {
    let dir = std::env::temp_dir().join(format!(
        "veil-reg-failint-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("caller_registry.json");
    let mut reg = CallerRegistry::empty();
    reg.register("/s/a.sh", "h1").unwrap();
    reg.save_to(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    FAIL_INTEGRITY.with(|f| f.set(true));
    let err = reg.save_to(&path).unwrap_err();
    assert!(err.to_string().contains("完整性"), "{err}");
    assert!(!path.with_extension("tmp").exists(), "失败不得残留 tmp");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "原文件字节不得被覆盖"
    );
    let err = CallerRegistry::load_from(&path).unwrap_err();
    assert!(err.to_string().contains("完整性"), "{err}");
    FAIL_INTEGRITY.with(|f| f.set(false));
    assert!(CallerRegistry::load_from(&path).is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn registry_write_fsync() {
    // C14/D14：落盘原子 + fsync（tmp sync_all，rename 后父目录 fsync）。
    let dir = std::env::temp_dir().join(format!(
        "veil-reg-fsync-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("caller_registry.json");
    let mut reg = CallerRegistry::empty();
    reg.register("/s/fs.sh", "fs-h1").unwrap();
    reg.save_to(&path).unwrap();
    let loaded = CallerRegistry::load_from(&path).unwrap();
    assert_eq!(loaded.len(), 1, "fsync 落盘后须可完整加载");
    // 落盘失败注入：fsync 失败须显式报错、不留 tmp、不覆盖原文件。
    let before = std::fs::read(&path).unwrap();
    FAIL_SYNC.with(|f| f.set(true));
    let err = reg.save_to(&path).unwrap_err();
    assert!(err.to_string().contains("fsync"), "{err}");
    assert!(!path.with_extension("tmp").exists(), "失败不得残留 tmp");
    assert_eq!(std::fs::read(&path).unwrap(), before, "原文件不得被覆盖");
    FAIL_SYNC.with(|f| f.set(false));
    // 损坏文件加载返回 Err，不回落空表（fail-closed）。
    std::fs::write(&path, b"{broken").unwrap();
    assert!(
        CallerRegistry::load_from(&path).is_err(),
        "损坏须 fail-closed"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn bind_script_size_cap() {
    let dir = std::env::temp_dir().join(format!(
        "veil-reg-bindcap-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let big = dir.join("big.sh");
    let file = std::fs::File::create(&big).unwrap();
    file.set_len(BIND_SCRIPT_MAX_BYTES + 1).unwrap();
    drop(file);
    let big_str = big.to_string_lossy().into_owned();
    let got = bind_script_sha256_async(big_str.clone(), "cap-h".to_string()).await;
    assert_eq!(
        got,
        derived_script_sha256("cap-h", &big_str),
        "超限文件须回退派生且结果与公式一致"
    );
    let small = dir.join("small.sh");
    std::fs::write(&small, b"echo hi").unwrap();
    let small_str = small.to_string_lossy().into_owned();
    let got = bind_script_sha256_async(small_str, "cap-h".to_string()).await;
    assert_eq!(got, script_sha256_of_bytes(b"echo hi"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn bind_script_path_length() {
    let too_long = format!("/nonexistent/{}.sh", "a".repeat(BIND_SCRIPT_MAX_PATH_LEN));
    let got = bind_script_sha256_async(too_long.clone(), "len-h".to_string()).await;
    assert_eq!(got, derived_script_sha256("len-h", &too_long));
    assert_eq!(bind_script_sha256(&too_long, "len-h"), got);
}

#[test]
fn bind_script_relative_path() {
    let rel = "relative/scripts/job.sh";
    let abs = "/nonexistent/scripts/job.sh";
    assert_eq!(
        bind_script_sha256(rel, "rel-h"),
        derived_script_sha256("rel-h", rel),
        "相对路径未被拒绝（仅长度/大小校验，decision D5）"
    );
    assert_eq!(
        bind_script_sha256(abs, "rel-h"),
        derived_script_sha256("rel-h", abs)
    );
    assert_eq!(
        bind_script_sha256(rel, "rel-h"),
        bind_script_sha256(rel, "rel-h")
    );
}
