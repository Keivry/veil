//! 命令执行后端：argv 白名单、固定工作目录、最小环境、超时 kill 与有界输出。
//!
//! 同步原语只在阻塞上下文中调用：调用方 MUST 经 `tokio::task::spawn_blocking`
//! 进入本模块（由 `service::tests::tpm_sync_subprocess_guard` 的扩展扫描面约束）。
//! `program` 为绝对路径，参数以 argv 数组直接交给内核，SHALL NOT 经过 shell。

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// 单路输出默认上限（字节）。
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// 单路输出硬上限（配置/调用不得越过）。
pub const MAX_OUTPUT_BYTES_LIMIT: usize = 1024 * 1024;
/// 超时轮询粒度。
const WAIT_POLL: Duration = Duration::from_millis(10);

/// 一次执行的原始结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub truncated: bool,
}

impl CommandOutput {
    pub fn success(&self) -> bool { !self.timed_out && self.exit_code == Some(0) }
}

/// 可插拔执行后端边界；本期仅本机实现。
pub trait CommandBackend: Send + Sync {
    fn run_blocking(
        &self,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> anyhow::Result<CommandOutput>;
}

/// 本机后端。
#[derive(Debug, Clone)]
pub struct LocalBackend {
    work_dir: PathBuf,
    max_output_bytes: usize,
}

impl LocalBackend {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    pub fn with_max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = bytes.clamp(1, MAX_OUTPUT_BYTES_LIMIT);
        self
    }
}

impl CommandBackend for LocalBackend {
    fn run_blocking(
        &self,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> anyhow::Result<CommandOutput> {
        if !program.is_absolute() {
            anyhow::bail!("program 须为绝对路径: {}", program.display());
        }
        std::fs::create_dir_all(&self.work_dir)?;
        let mut child = Command::new(program)
            .args(args)
            .current_dir(&self.work_dir)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdout 管道缺失"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("stderr 管道缺失"))?;
        let limit = self.max_output_bytes;
        let start = Instant::now();
        let out_reader = std::thread::spawn(move || read_capped(stdout, limit));
        let err_reader = std::thread::spawn(move || read_capped(stderr, limit));

        let deadline = start + timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            std::thread::sleep(WAIT_POLL);
        };

        let (stdout, stdout_truncated) = out_reader
            .join()
            .map_err(|_| anyhow::anyhow!("stdout 读取线程异常"))?;
        let (stderr, stderr_truncated) = err_reader
            .join()
            .map_err(|_| anyhow::anyhow!("stderr 读取线程异常"))?;
        Ok(CommandOutput {
            exit_code: status.and_then(|s| s.code()),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
            timed_out,
            truncated: stdout_truncated || stderr_truncated,
        })
    }
}

fn read_capped(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::with_capacity(limit.min(8192));
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = limit.saturating_sub(kept.len());
                if n > remaining {
                    truncated = true;
                }
                let take = n.min(remaining);
                kept.extend_from_slice(&buf[..take]);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (kept, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> LocalBackend { LocalBackend::new(std::env::temp_dir()) }

    fn args(items: &[&str]) -> Vec<String> { items.iter().map(|s| (*s).to_string()).collect() }

    #[test]
    fn argv_passed_without_shell_interpretation() {
        let out = local()
            .run_blocking(
                Path::new("/bin/echo"),
                &args(&["a;b", "$(id)", "x y"]),
                Duration::from_secs(5),
            )
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.trim_end(), "a;b $(id) x y");
        assert!(!out.timed_out);
    }

    #[test]
    fn timeout_kills_child() {
        let out = local()
            .run_blocking(
                Path::new("/bin/sleep"),
                &args(&["5"]),
                Duration::from_millis(150),
            )
            .unwrap();
        assert!(out.timed_out);
        assert!(out.duration_ms < 3000);
    }

    #[test]
    fn output_is_truncated_with_marker() {
        let out = LocalBackend::new(std::env::temp_dir())
            .with_max_output_bytes(1024)
            .run_blocking(
                Path::new("/usr/bin/yes"),
                &args(&["y"]),
                Duration::from_millis(150),
            )
            .unwrap();
        assert!(out.truncated);
        assert!(out.stdout.len() <= 1024);
    }

    #[test]
    fn nonzero_exit_is_reported() {
        let out = local()
            .run_blocking(Path::new("/bin/false"), &[], Duration::from_secs(5))
            .unwrap();
        assert_eq!(out.exit_code, Some(1));
        assert!(!out.success());
        assert!(!out.timed_out);
    }
}
