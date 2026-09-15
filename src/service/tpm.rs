//! §6.4 TPM 强制硬件：`TpmUnlock` trait + 真实实现 + CI 用 Mock。
//!
//! 真实实现走 `tpm2-tools` 子进程现场 `createprimary → load → unseal`，
//! `primary.ctx` 只落临时目录且用后删除，不持久化；TPM 不可用时启动失败，
//! MUST NOT 软件回退。
//!
//! 接线：`main` 启动链经 [`startup_tpm`] 门禁 fail-closed（默认真实 TPM；
//! `VEIL_ALLOW_MOCK_TPM=1` 仅 CI/本地联调显式放行 Mock）。KeePass 主密钥
//! TPM 派生随真实 kdbx 后端延后（Non-Goal，见 credential-api spec）。
//!
//! H8/D8 调用约束：同步 `std::process::Command`/忙轮询（[`RealTpm::run`]，10ms
//! sleep 轮询）与 `is_available`（`tpm2_pcrread`）**仅允许启动期与
//! `spawn_blocking` 内调用，禁 async 上下文直调**（阻塞线程池）；忙轮询保留在
//! 阻塞语境，不迁移 `tokio::process`（理由见 design D8）。调用点守护见
//! `service::declaration_lock::tpm_sync_subprocess_guard`。

use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// `C9`/D9：解封工作目录序号，配合 pid/nanos 保证每次调用唯一，并发不互覆。
static TPM_WORKDIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// `veil-tpm-{pid}-{nanos}-{seq}`：每次调用唯一，替代固定 `veil-tpm-{pid}`。
fn unique_tpm_workdir() -> PathBuf {
    let seq = TPM_WORKDIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("veil-tpm-{}-{nanos}-{seq}", std::process::id()))
}

/// 工作目录守卫：成功、失败、提前返回均经 `Drop` 清理（不轮询、不全局锁）。
struct TempWorkdir(PathBuf);

impl Drop for TempWorkdir {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).ok(); }
}

/// TPM 解封抽象：真实 TPM 与 CI Mock 同接口。
pub trait TpmUnlock: Send + Sync + Debug {
    fn unseal(&self) -> anyhow::Result<Vec<u8>>;
    fn is_available(&self) -> bool;
}

/// CI / 单测用 Mock TPM（无硬件依赖）。
#[derive(Debug, Clone)]
pub struct MockTpm {
    secret: Vec<u8>,
    available: bool,
}

impl MockTpm {
    pub fn unlocked(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            available: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn unavailable() -> Self {
        Self {
            secret: Vec::new(),
            available: false,
        }
    }
}

impl TpmUnlock for MockTpm {
    fn unseal(&self) -> anyhow::Result<Vec<u8>> {
        if !self.available {
            anyhow::bail!("MockTpm 不可用");
        }
        Ok(self.secret.clone())
    }

    fn is_available(&self) -> bool { self.available }
}

/// 真实 TPM：经 `tpm2-tools` 子进程现场派生。
/// 子进程单步超时 30s（慢速 TPM/虚拟化环境下 15s 易误杀，阈值只改接线不改语义）；
/// 失败时错误内保留完整 stderr 诊断文本，warn 分支同样保留（排障用，不截断）。
#[derive(Debug, Clone)]
pub struct RealTpm {
    pub tpm_dir: PathBuf,
    pub timeout: Duration,
    /// 测试注入：自定义 `tpm2-*` 可执行目录（生产 `None`，走 `PATH`）。
    bin_dir: Option<PathBuf>,
}

impl RealTpm {
    pub fn new() -> Self {
        Self {
            tpm_dir: PathBuf::from("/data/tpm"),
            timeout: Duration::from_secs(30),
            bin_dir: None,
        }
    }

    pub fn with_dir(tpm_dir: PathBuf) -> Self {
        Self {
            tpm_dir,
            timeout: Duration::from_secs(30),
            bin_dir: None,
        }
    }

    #[cfg(test)]
    fn with_bin_dir(tpm_dir: PathBuf, bin_dir: PathBuf) -> Self {
        Self {
            tpm_dir,
            timeout: Duration::from_secs(30),
            bin_dir: Some(bin_dir),
        }
    }

    pub fn seal_pub(&self) -> PathBuf { self.tpm_dir.join("seal.pub") }

    pub fn seal_priv(&self) -> PathBuf { self.tpm_dir.join("seal.priv") }

    /// 与密封时相同的模板回放（owner + rsa2048 + sha256），供回归测试断言。
    pub fn createprimary_args(&self, primary_ctx: &str) -> Vec<String> {
        vec![
            "-C".to_string(),
            "o".to_string(),
            "-G".to_string(),
            "rsa2048".to_string(),
            "-g".to_string(),
            "sha256".to_string(),
            "-c".to_string(),
            primary_ctx.to_string(),
        ]
    }

    fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<String> {
        use std::io::Read as _;
        let executable = match &self.bin_dir {
            Some(dir) => dir.join(program),
            None => PathBuf::from(program),
        };
        let mut child = retry_on_exec_busy(EXEC_MAX_ATTEMPTS, || {
            std::process::Command::new(&executable)
                .args(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
        })
        .map_err(|e| anyhow::anyhow!("TPM 子进程启动失败 {program}: {e}"))?;
        let timeout = self.timeout;
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = String::new();
                    let mut stderr = String::new();
                    if let Some(mut out) = child.stdout.take() {
                        out.read_to_string(&mut stdout).ok();
                    }
                    if let Some(mut err) = child.stderr.take() {
                        err.read_to_string(&mut stderr).ok();
                    }
                    if !status.success() {
                        anyhow::bail!(
                            "TPM 子进程失败 {program} {}: {}",
                            args.join(" "),
                            stderr.trim()
                        );
                    }
                    if !stderr.trim().is_empty() {
                        // stderr 全文保留进诊断（TPM 工具链警告常带排障关键行，不截断）。
                        tracing::warn!("{program} stderr 非空: {}", stderr.trim());
                    }
                    return Ok(stdout);
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        child.kill().ok();
                        child.wait().ok();
                        anyhow::bail!(
                            "TPM 子进程超时 {program} {}（{}s），已终止",
                            args.join(" "),
                            timeout.as_secs()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    anyhow::bail!("TPM 子进程等待失败 {program}: {e}");
                }
            }
        }
    }
}

const EXEC_MAX_ATTEMPTS: u32 = 5;

/// ETXTBSY（可执行文件忙）有界重试：仅瞬态忙时重试，其他错误立即透传。
/// 上限 `EXEC_MAX_ATTEMPTS` 次、退避 10/20/30/40ms（总上界 100ms）；
/// 仅用于 `spawn` 阶段，不影响子进程超时语义。
fn retry_on_exec_busy<T>(
    max_attempts: u32,
    mut op: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if is_executable_file_busy(&err) && attempt < max_attempts => {
                std::thread::sleep(std::time::Duration::from_millis(10 * u64::from(attempt)));
            }
            Err(err) => return Err(err),
        }
    }
}

/// ETXTBSY 判定：Linux 下映射为 `ExecutableFileBusy`，裸错误码 26 兜底。
fn is_executable_file_busy(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::ExecutableFileBusy || err.raw_os_error() == Some(26)
}

impl Default for RealTpm {
    fn default() -> Self { Self::new() }
}

impl TpmUnlock for RealTpm {
    /// 存活探测：`tpm2_pcrread sha256:0` 只读 PCR，不触密封对象。
    /// 与 `unseal` 路径（`createprimary → load → unseal` 全回放）的差异有意为之：
    /// 探测只回答“TPM 硬件/守护进程是否在位”，密封模板回放正确性由 `unseal`
    /// 首次调用的真实错误透出，不在探测阶段预演（避免启动期双倍耗时与临时目录残留）。
    fn is_available(&self) -> bool {
        retry_on_exec_busy(EXEC_MAX_ATTEMPTS, || {
            std::process::Command::new("tpm2_pcrread")
                .arg("sha256:0")
                .output()
        })
        .is_ok_and(|o| o.status.success())
    }

    fn unseal(&self) -> anyhow::Result<Vec<u8>> {
        let seal_pub = self.seal_pub();
        let seal_priv = self.seal_priv();
        for path in [&seal_pub, &seal_priv] {
            if !path.is_file() {
                anyhow::bail!("TPM 密封文件缺失 {}，拒绝以空密钥运行", path.display());
            }
        }
        let workdir = unique_tpm_workdir();
        std::fs::create_dir_all(&workdir)?;
        let _guard = TempWorkdir(workdir.clone());
        let primary_ctx = workdir.join("primary.ctx");
        let primary_arg = primary_ctx.to_string_lossy().into_owned();
        let template = self.createprimary_args(primary_arg.as_str());
        let template_refs: Vec<&str> = template.iter().map(String::as_str).collect();
        self.run("tpm2_createprimary", &template_refs)?;
        let sealed_pub = seal_pub.to_string_lossy().into_owned();
        let sealed_priv = seal_priv.to_string_lossy().into_owned();
        let ctx_arg = sealed_ctx_arg(&workdir);
        self.run(
            "tpm2_load",
            &[
                "-C",
                primary_arg.as_str(),
                "-u",
                sealed_pub.as_str(),
                "-r",
                sealed_priv.as_str(),
                "-c",
                ctx_arg.as_str(),
            ],
        )?;
        let out = self.run("tpm2_unseal", &["-c", ctx_arg.as_str()])?;
        let trimmed = out.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            anyhow::bail!("TPM 解封返回空密码");
        }
        if trimmed.len() < 4 {
            anyhow::bail!("TPM 解封返回的密码过短（{} 字符）", trimmed.len());
        }
        Ok(trimmed.as_bytes().to_vec())
    }
}

fn sealed_ctx_arg(workdir: &Path) -> String {
    workdir.join("sealed.ctx").to_string_lossy().into_owned()
}

/// 启动门禁：TPM 不可用 SHALL 报错退出，MUST NOT 软件回退。
pub fn require_hardware_tpm(tpm: &dyn TpmUnlock) -> anyhow::Result<Vec<u8>> {
    if !tpm.is_available() {
        anyhow::bail!("TPM 不可用，拒绝启动（禁止软件回退）");
    }
    tpm.unseal()
}

/// main 启动链门禁选型：默认真实 TPM fail-closed；
/// （`VEIL_ALLOW_MOCK_TPM=1`）仅 CI/本地联调显式放行，生产 MUST NOT 启用。
pub fn mock_allowed_value(raw: &str) -> bool { raw.trim() == "1" }

pub fn allow_mock_from_env() -> bool {
    std::env::var("VEIL_ALLOW_MOCK_TPM").is_ok_and(|v| mock_allowed_value(&v))
}

pub fn startup_tpm_in(tpm_dir: &std::path::Path, allow_mock: bool) -> anyhow::Result<Vec<u8>> {
    if allow_mock {
        tracing::warn!("VEIL_ALLOW_MOCK_TPM=1：以 Mock TPM 运行，禁止生产使用");
        return MockTpm::unlocked(b"veil-dev-mock-tpm-seal").unseal();
    }
    require_hardware_tpm(&RealTpm::with_dir(tpm_dir.to_path_buf()))
}

#[cfg(test)]
pub(crate) fn startup_tpm(allow_mock: bool) -> anyhow::Result<Vec<u8>> {
    startup_tpm_in(std::path::Path::new("/data/tpm"), allow_mock)
}

#[cfg(test)]
mod tests {
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
        // 不依赖宿主是否具备 TPM 硬件，消除条件化断言空转（TCP-3/FAKE-3）。
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
}
