use super::*;

#[test]
fn ci_mock_unlocks_and_passes_gate() {
    let mock = MockTpm::unlocked(b"supersecret");
    assert!(mock.is_available());
    assert_eq!(mock.unseal().unwrap(), b"supersecret");
    let sealed = require_hardware_tpm(&mock).unwrap();
    assert_eq!(sealed, b"supersecret");
}

#[test]
fn unavailable_tpm_fails_startup_without_software_fallback() {
    // 注入桩（MockTpm::unavailable）：确定性覆盖「不可用即 fail-closed、禁止软件回退」，
    // 不依赖宿主是否具备 TPM 硬件，消除条件化断言空转。
    let mock = MockTpm::unavailable();
    assert!(!mock.is_available());
    assert!(mock.unseal().is_err());
    let err = require_hardware_tpm(&mock).unwrap_err().to_string();
    assert!(err.contains("TPM") && err.contains("拒绝启动"), "{err}");
    assert!(err.contains("软件回退"), "{err}");
}

#[test]
fn real_impl_persists_no_primary_ctx() {
    // primary.ctx 只允许出现在临时目录拼装路径中，仓库内不得存在持久化文件。
    assert!(!std::path::Path::new("primary.ctx").exists());
    assert!(!std::path::Path::new("/data/primary.ctx").exists());
}

#[test]
fn startup_gate_explicit_mock_allowed() {
    let sealed = startup_tpm(true).unwrap();
    assert!(!sealed.is_empty());
}

#[test]
fn startup_gate_defaults_to_hardware_and_fails_without_it() {
    // 注入桩：始终不可用的 TpmUnlock，门禁确定性 fail-closed（真实断言，不空转）。
    let unavailable = MockTpm::unavailable();
    let err = require_hardware_tpm(&unavailable).unwrap_err().to_string();
    assert!(err.contains("TPM") && err.contains("拒绝启动"), "{err}");
    // 默认硬件门禁走真实 RealTpm 构造：无硬件 → "TPM 不可用"；
    // 有硬件但空密封目录 → "密封文件缺失"；两分支恒为 Err，断言无条件执行。
    let dir = unique_test_base("startup-hw-default");
    std::fs::create_dir_all(&dir).unwrap();
    let result = startup_tpm_in(&dir, false);
    assert!(
        result.is_err(),
        "默认硬件门禁在缺密封材料时不得放行: {result:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn template_replay_contains_owner_rsa2048_sha256() {
    let tpm = RealTpm::with_dir(PathBuf::from("/data/tpm"));
    let args = tpm.createprimary_args("primary.ctx");
    let joined = args.join(" ");
    assert!(joined.contains("-C") && joined.contains('o'), "{joined}");
    assert!(joined.contains("rsa2048"), "{joined}");
    assert!(joined.contains("sha256"), "{joined}");
}

#[test]
fn seal_paths_come_from_tpm_dir() {
    let tpm = RealTpm::with_dir(PathBuf::from("/srv/tpm"));
    assert_eq!(tpm.seal_pub(), PathBuf::from("/srv/tpm/seal.pub"));
    assert_eq!(tpm.seal_priv(), PathBuf::from("/srv/tpm/seal.priv"));
    assert_eq!(
        RealTpm::new().seal_pub(),
        PathBuf::from("/data/tpm/seal.pub")
    );
}

#[test]
fn missing_seal_files_reject_empty_key() {
    let dir = std::env::temp_dir().join(format!(
        "veil-tpm-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let tpm = RealTpm::with_dir(dir.clone());
    let err = tpm.unseal().unwrap_err().to_string();
    assert!(
        err.contains("密封文件缺失") && err.contains("空密钥"),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mock_gate_allows_only_exact_one() {
    assert!(mock_allowed_value("1"));
    for raw in ["true", "True", "0", "", "  ", "01", "1 "] {
        if raw == "1 " {
            assert!(mock_allowed_value(raw), "{raw:?} 去空格后应放行");
        } else {
            assert!(!mock_allowed_value(raw), "{raw:?} 须走硬件门禁");
        }
    }
    assert!(!mock_allowed_value("true"));
}

#[test]
fn timeout_defaults_to_30_seconds() {
    assert_eq!(RealTpm::new().timeout, Duration::from_secs(30));
    assert_eq!(
        RealTpm::with_dir(PathBuf::from("/x")).timeout,
        Duration::from_secs(30)
    );
}

#[test]
fn retry_on_exec_busy_transient_busy_then_ok() {
    let mut calls = 0u32;
    let out = retry_on_exec_busy(EXEC_MAX_ATTEMPTS, || {
        calls += 1;
        if calls < 3 {
            Err(std::io::Error::from_raw_os_error(26))
        } else {
            Ok(calls)
        }
    })
    .expect("瞬态忙后须成功");
    assert_eq!(out, 3);
    assert_eq!(calls, 3, "忙碌两次后第三次成功：尝试次数须为 3");
}

#[test]
fn retry_on_exec_busy_non_busy_error_passthrough() {
    let mut calls = 0u32;
    let err = retry_on_exec_busy(EXEC_MAX_ATTEMPTS, || {
        calls += 1;
        Err::<u32, _>(std::io::Error::from_raw_os_error(2))
    })
    .expect_err("非忙错误须透传");
    assert_eq!(calls, 1, "非 ETXTBSY 不得重试");
    assert_eq!(err.raw_os_error(), Some(2));
}

#[test]
fn retry_on_exec_busy_exhausts_and_returns_last() {
    let mut calls = 0u32;
    let err = retry_on_exec_busy(EXEC_MAX_ATTEMPTS, || {
        calls += 1;
        Err::<u32, _>(std::io::Error::from_raw_os_error(26))
    })
    .expect_err("持续忙须达上限后报错");
    assert_eq!(calls, EXEC_MAX_ATTEMPTS, "尝试次数须恰为上限");
    assert_eq!(err.raw_os_error(), Some(26));
}

fn unique_test_base(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "veil-tpm-test-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    // sync_all 让写者尽快落定，缩小 exec 与写入的竞争窗口（兜底见 retry_on_exec_busy）。
    let mut file = std::fs::File::create(path).unwrap();
    std::io::Write::write_all(&mut file, body.as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut perm = std::fs::metadata(path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm).unwrap();
}

/// 伪造 `tpm2-*` 工具：`createprimary` 将 `-c` 目标路径追加日志（可观测工作目录），
/// `load` 直通，`unseal` 按用例返回固定密码或失败；使并发/清理路径可确定性验证。
fn fake_tpm(tag: &str, unseal_ok: bool) -> (PathBuf, PathBuf, RealTpm) {
    let base = unique_test_base(tag);
    let seal_dir = base.join("seal");
    let bin_dir = base.join("bin");
    std::fs::create_dir_all(&seal_dir).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(seal_dir.join("seal.pub"), b"pub").unwrap();
    std::fs::write(seal_dir.join("seal.priv"), b"priv").unwrap();
    let log = base.join("calls.log");
    let log_lit = log.to_string_lossy().into_owned();
    write_executable(
        &bin_dir.join("tpm2_createprimary"),
        &format!("#!/bin/sh\necho \"$*\" >> \"{log_lit}\"\nexit 0\n"),
    );
    write_executable(&bin_dir.join("tpm2_load"), "#!/bin/sh\nexit 0\n");
    if unseal_ok {
        write_executable(
            &bin_dir.join("tpm2_unseal"),
            "#!/bin/sh\necho secret-password\nexit 0\n",
        );
    } else {
        write_executable(
            &bin_dir.join("tpm2_unseal"),
            "#!/bin/sh\necho boom >&2\nexit 1\n",
        );
    }
    (base, log, RealTpm::with_bin_dir(seal_dir, bin_dir))
}

fn logged_workdirs(log: &Path) -> Vec<PathBuf> {
    let content = std::fs::read_to_string(log).unwrap_or_default();
    let mut dirs = Vec::new();
    for line in content.lines() {
        let mut prev = "";
        for tok in line.split_whitespace() {
            if prev == "-c"
                && let Some(parent) = Path::new(tok).parent()
            {
                dirs.push(parent.to_path_buf());
            }
            prev = tok;
        }
    }
    dirs
}

#[test]
fn tpm_concurrent_unseal_isolated() {
    let (base, log, tpm) = fake_tpm("concurrent", true);
    let n = 16;
    let mut handles = Vec::new();
    for _ in 0..n {
        let tpm = tpm.clone();
        handles.push(std::thread::spawn(move || tpm.unseal()));
    }
    for handle in handles {
        let out = handle
            .join()
            .expect("解封线程不得 panic")
            .expect("并发解封须成功");
        assert_eq!(out, b"secret-password");
    }
    let dirs = logged_workdirs(&log);
    let unique: std::collections::HashSet<&PathBuf> = dirs.iter().collect();
    assert_eq!(dirs.len(), n, "每次解封须各记录一次工作目录");
    assert_eq!(unique.len(), n, "并发工作目录必须互不相同");
    for dir in &dirs {
        assert!(dir.to_string_lossy().contains("veil-tpm-"), "{dir:?}");
        assert!(!dir.exists(), "解封后工作目录须清理: {dir:?}");
    }
    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn tpm_tempdir_cleanup() {
    let (base, log, tpm) = fake_tpm("cleanup-ok", true);
    assert_eq!(tpm.unseal().expect("成功解封"), b"secret-password");
    for dir in logged_workdirs(&log) {
        assert!(!dir.exists(), "成功路径不得残留临时目录: {dir:?}");
    }
    std::fs::remove_dir_all(&base).ok();

    let (base, log, tpm) = fake_tpm("cleanup-fail", false);
    assert!(tpm.unseal().is_err(), "tpm2_unseal 失败须透出错误");
    for dir in logged_workdirs(&log) {
        assert!(!dir.exists(), "失败路径不得残留临时目录: {dir:?}");
    }
    std::fs::remove_dir_all(&base).ok();

    let base = unique_test_base("cleanup-missing");
    std::fs::create_dir_all(&base).unwrap();
    let tpm = RealTpm::with_dir(base.join("empty"));
    let err = tpm.unseal().unwrap_err();
    assert!(err.to_string().contains("密封文件缺失"), "{err}");
    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn probe_reports_missing_tool_with_actionable_hint() {
    let base = unique_test_base("probe-missing");
    let bin_dir = base.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let tpm = RealTpm::with_bin_dir(base.join("seal"), bin_dir);
    let err = tpm.probe().unwrap_err();
    assert!(err.contains("tpm2_pcrread 不存在"), "{err}");
    assert!(err.contains("tpm2-tools"), "{err}");
    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn probe_surfaces_stderr_and_permission_hint() {
    let base = unique_test_base("probe-stderr");
    let bin_dir = base.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(
        &bin_dir.join("tpm2_pcrread"),
        "#!/bin/sh\necho 'pcrread boom detail' >&2\nexit 1\n",
    );
    let tpm = RealTpm::with_bin_dir(base.join("seal"), bin_dir.clone());
    let err = tpm.probe().unwrap_err();
    assert!(err.contains("pcrread boom detail"), "{err}");
    assert!(!err.contains("group_add"), "{err}");

    write_executable(
        &bin_dir.join("tpm2_pcrread"),
        "#!/bin/sh\necho 'ERROR: Permission denied' >&2\nexit 1\n",
    );
    let err = tpm.probe().unwrap_err();
    assert!(err.contains("Permission denied"), "{err}");
    assert!(err.contains("group_add TPM_GID"), "{err}");
    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn probe_succeeds_with_zero_exit_and_gate_prepends_reason() {
    let base = unique_test_base("probe-ok");
    let bin_dir = base.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(&bin_dir.join("tpm2_pcrread"), "#!/bin/sh\nexit 0\n");
    let tpm = RealTpm::with_bin_dir(base.join("seal"), bin_dir);
    assert!(tpm.probe().is_ok());
    std::fs::remove_dir_all(&base).ok();

    let err = require_hardware_tpm(&MockTpm::unavailable()).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("TPM 不可用，拒绝启动（禁止软件回退）"),
        "{text}"
    );
    assert!(text.contains("TPM 不可用"), "{text}");
}
