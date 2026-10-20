//! TPM 强制硬件：`TpmUnlock` trait + 真实实现 + CI 用 Mock。
//!
//! 真实实现走 `tpm2-tools` 子进程现场 `createprimary → load → unseal`，
//! `primary.ctx` 只落临时目录且用后删除，不持久化；TPM 不可用时启动失败，
//! MUST NOT 软件回退。
//!
//! 接线：`main` 启动链经 [`startup_tpm_in`] 门禁 fail-closed（默认真实 TPM；
//! `VEIL_ALLOW_MOCK_TPM=1` 仅 CI/本地联调显式放行 Mock）。KeePass 主密钥
//! TPM 派生随真实 kdbx 后端延后（Non-Goal）。
//!
//! 调用约束：同步 `std::process::Command`/忙轮询（`RealTpm::run`，10ms
//! sleep 轮询）与 `is_available`（`tpm2_pcrread`）**仅允许启动期与
//! `spawn_blocking` 内调用，禁 async 上下文直调**（阻塞线程池）；忙轮询保留在
//! 阻塞语境，不迁移 `tokio::process`。调用点守护见
//! `service::declaration_lock::tpm_sync_subprocess_guard`。

use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// 解封工作目录序号，配合 pid/nanos 保证每次调用唯一，并发不互覆。
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

    /// 带因由的可用性探测：默认由 `is_available` 降级（Mock 走此路径）。
    fn probe(&self) -> std::result::Result<(), String> {
        if self.is_available() {
            Ok(())
        } else {
            Err("TPM 不可用".to_string())
        }
    }
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
    fn is_available(&self) -> bool { self.probe().is_ok() }

    /// 探测 `tpm2_pcrread` 并保留 stderr：缺失/非零退出/设备权限不足给出可区分的启动原因。
    fn probe(&self) -> std::result::Result<(), String> {
        let executable = match &self.bin_dir {
            Some(dir) => dir.join("tpm2_pcrread"),
            None => PathBuf::from("tpm2_pcrread"),
        };
        let output = match retry_on_exec_busy(EXEC_MAX_ATTEMPTS, || {
            std::process::Command::new(&executable)
                .arg("sha256:0")
                .output()
        }) {
            Ok(output) => output,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err("tpm2_pcrread 不存在（runtime 镜像需安装 tpm2-tools）".to_string());
            }
            Err(err) => return Err(format!("tpm2_pcrread 执行失败: {err}")),
        };
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let reason = if stderr.is_empty() {
            format!("tpm2_pcrread 退出码 {:?}", output.status.code())
        } else {
            stderr
        };
        if reason.contains("Permission denied") || reason.contains("EACCES") {
            return Err(format!(
                "{reason}（设备权限不足：容器内需 group_add TPM_GID 或调整设备属组）"
            ));
        }
        Err(reason)
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
    if let Err(reason) = tpm.probe() {
        anyhow::bail!("TPM 不可用，拒绝启动（禁止软件回退）: {reason}");
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
mod tests;
