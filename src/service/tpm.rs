//! §6.4 TPM 强制硬件：`TpmUnlock` trait + 真实实现 + CI 用 Mock。
//!
//! 真实实现走 `tpm2-tools` 子进程现场 `createprimary → load → unseal`，
//! `primary.ctx` 只落临时目录且用后删除，不持久化；TPM 不可用时启动失败，
//! MUST NOT 软件回退。
//!
//! 接线：`main` 启动链经 [`startup_tpm`] 门禁 fail-closed（默认真实 TPM；
//! `VEIL_ALLOW_MOCK_TPM=1` 仅 CI/本地联调显式放行 Mock）。KeePass 主密钥
//! TPM 派生随真实 kdbx 后端延后（Non-Goal，见 credential-api spec）。

use std::{fmt::Debug, path::PathBuf, time::Duration};

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

    pub fn unavailable() -> Self {
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
}

impl RealTpm {
    pub fn new() -> Self {
        Self {
            tpm_dir: PathBuf::from("/data/tpm"),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_dir(tpm_dir: PathBuf) -> Self {
        Self {
            tpm_dir,
            timeout: Duration::from_secs(30),
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
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
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

impl Default for RealTpm {
    fn default() -> Self { Self::new() }
}

impl TpmUnlock for RealTpm {
    /// 存活探测：`tpm2_pcrread sha256:0` 只读 PCR，不触密封对象。
    /// 与 `unseal` 路径（`createprimary → load → unseal` 全回放）的差异有意为之：
    /// 探测只回答“TPM 硬件/守护进程是否在位”，密封模板回放正确性由 `unseal`
    /// 首次调用的真实错误透出，不在探测阶段预演（避免启动期双倍耗时与临时目录残留）。
    fn is_available(&self) -> bool {
        std::process::Command::new("tpm2_pcrread")
            .arg("sha256:0")
            .output()
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
        let workdir = std::env::temp_dir().join(format!("veil-tpm-{}", std::process::id()));
        std::fs::create_dir_all(&workdir)?;
        struct Guard(PathBuf);
        impl Drop for Guard {
            fn drop(&mut self) { std::fs::remove_dir_all(&self.0).ok(); }
        }
        let _guard = Guard(workdir.clone());
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

fn sealed_ctx_arg(workdir: &std::path::Path) -> String {
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

pub fn startup_tpm(allow_mock: bool) -> anyhow::Result<Vec<u8>> {
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
        let mock = MockTpm::unavailable();
        assert!(!mock.is_available());
        assert!(mock.unseal().is_err());
        let err = require_hardware_tpm(&mock).unwrap_err().to_string();
        assert!(err.contains("TPM") && err.contains("软件回退"), "{err}");
        // 真实 TPM 在无硬件 CI 环境下 is_available 为 false，且 unseal 不返回静默密钥。
        let real = RealTpm::new();
        if !real.is_available() {
            assert!(require_hardware_tpm(&real).is_err());
        }
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
        if !RealTpm::new().is_available() {
            assert!(startup_tpm(false).is_err());
        }
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
}
