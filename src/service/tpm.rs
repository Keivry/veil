//! §6.4 TPM 强制硬件：`TpmUnlock` trait + 真实实现 + CI 用 Mock。
//!
//! 真实实现走 `tpm2-tools` 子进程现场 `createprimary → load → unseal`，
//! `primary.ctx` 只落临时目录且用后删除，不持久化；TPM 不可用时启动失败，
//! MUST NOT 软件回退。
//!
//! TODO(§6): KeePass 主密钥派生接入点需在 `keepass` 侧调用 [`require_hardware_tpm`]；
//! 本文件只提供 TPM 能力，不改其文件。

use std::{fmt::Debug, path::PathBuf, process::Command, time::Duration};

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
#[derive(Debug, Clone)]
pub struct RealTpm {
    pub key_context: Option<PathBuf>,
    pub timeout: Duration,
}

impl RealTpm {
    pub fn new() -> Self {
        Self {
            key_context: None,
            timeout: Duration::from_secs(15),
        }
    }

    fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<String> {
        let out = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("TPM 子进程启动失败 {program}: {e}"))?;
        if !out.status.success() {
            anyhow::bail!(
                "TPM 子进程失败 {program} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl Default for RealTpm {
    fn default() -> Self { Self::new() }
}

impl TpmUnlock for RealTpm {
    fn is_available(&self) -> bool {
        Command::new("tpm2_pcrread")
            .arg("sha256:0")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn unseal(&self) -> anyhow::Result<Vec<u8>> {
        let workdir = std::env::temp_dir().join(format!("veil-tpm-{}", std::process::id()));
        std::fs::create_dir_all(&workdir)?;
        struct Guard(PathBuf);
        impl Drop for Guard {
            fn drop(&mut self) { std::fs::remove_dir_all(&self.0).ok(); }
        }
        let _guard = Guard(workdir.clone());
        let primary_ctx = workdir.join("primary.ctx");
        let primary_arg = primary_ctx.to_string_lossy().into_owned();
        // 现场 createprimary → 后续 load/unseal；primary.ctx 不持久化，随临时目录删除。
        self.run(
            "tpm2_createprimary",
            &["-C", "o", "-c", primary_arg.as_str()],
        )?;
        let sealed_pub = workdir.join("sealed.pub");
        let sealed_priv = workdir.join("sealed.priv");
        let ctx_arg = sealed_ctx_arg(&workdir);
        if let Some(persistent) = self.key_context.as_ref() {
            let p = persistent.to_string_lossy().into_owned();
            self.run(
                "tpm2_load",
                &[
                    "-C",
                    primary_arg.as_str(),
                    "-u",
                    p.as_str(),
                    "-r",
                    p.as_str(),
                    "-c",
                    ctx_arg.as_str(),
                ],
            )?;
        } else {
            let _ = (sealed_pub, sealed_priv);
            anyhow::bail!("TPM 无密封对象上下文，拒绝以空密钥运行");
        }
        let out = self.run("tpm2_unseal", &["-c", ctx_arg.as_str()])?;
        Ok(out.into_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci用mock全绿() {
        let mock = MockTpm::unlocked(b"supersecret");
        assert!(mock.is_available());
        assert_eq!(mock.unseal().unwrap(), b"supersecret");
        let sealed = require_hardware_tpm(&mock).unwrap();
        assert_eq!(sealed, b"supersecret");
    }

    #[test]
    fn tpm不可用启动失败且无软件回退() {
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
    fn 真实实现无持久化primary_ctx() {
        // primary.ctx 只允许出现在临时目录拼装路径中，仓库内不得存在持久化文件。
        assert!(!std::path::Path::new("primary.ctx").exists());
        assert!(!std::path::Path::new("/data/primary.ctx").exists());
    }
}
