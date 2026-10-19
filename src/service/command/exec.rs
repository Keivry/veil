//! 命令执行后端：argv 白名单、固定工作目录、最小环境、超时 kill 与有界输出。
//!
//! 同步原语只在阻塞上下文中调用：调用方 MUST 经 `tokio::task::spawn_blocking`
//! 进入本模块（由 `service::tests::tpm_sync_subprocess_guard` 的扩展扫描面约束）。
//! `program` 为绝对路径，参数以 argv 数组直接交给内核，SHALL NOT 经过 shell。

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    time::{Duration, Instant},
};

/// 子进程退出后等待 reader 收尾的宽限：孙进程可能继承管道并阻止 EOF。
#[cfg(target_os = "linux")]
const READER_GRACE: Duration = Duration::from_millis(500);
#[cfg(not(target_os = "linux"))]
const READER_GRACE: Duration = Duration::from_millis(2000);

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
    /// `host` 为逻辑执行目标；本机后端忽略，远程后端据此选路。
    fn run_blocking(
        &self,
        host: &str,
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
        _host: &str,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> anyhow::Result<CommandOutput> {
        if !program.is_absolute() {
            anyhow::bail!("program 须为绝对路径: {}", program.display());
        }
        std::fs::create_dir_all(&self.work_dir)?;
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(&self.work_dir)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // 独立进程组：超时可连同孙进程一并终止，避免其继承管道后 reader 永久阻塞。
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        let pid = child.id() as i32;
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
        let (out_tx, out_rx) = mpsc::channel();
        let (err_tx, err_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = out_tx.send(read_capped(stdout, limit));
        });
        std::thread::spawn(move || {
            let _ = err_tx.send(read_capped(stderr, limit));
        });

        let deadline = start + timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if Instant::now() >= deadline {
                timed_out = true;
                kill_process_group(pid);
                let _ = child.kill();
                break child.wait().ok();
            }
            std::thread::sleep(WAIT_POLL);
        };

        // 先按宽限收尾；孙进程滞留管道时强杀进程组，避免无限等待。
        let (stdout, stdout_truncated) = collect_reader(&out_rx, pid)?;
        let (stderr, stderr_truncated) = collect_reader(&err_rx, pid)?;
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

/// 收 reader 结果：超时则先杀进程组再等；仍无结果按空输出处理（不阻塞调用）。
fn collect_reader(
    rx: &mpsc::Receiver<(Vec<u8>, bool)>,
    pid: i32,
) -> anyhow::Result<(Vec<u8>, bool)> {
    match rx.recv_timeout(READER_GRACE) {
        Ok(value) => Ok(value),
        Err(RecvTimeoutError::Disconnected) => Ok((Vec::new(), false)),
        Err(RecvTimeoutError::Timeout) => {
            // 无条件再杀一次：孙进程可能在首次 SIGKILL 之后才 fork 并持有管道。
            kill_process_group(pid);
            match rx.recv_timeout(READER_GRACE) {
                Ok(value) => Ok(value),
                Err(_) => {
                    tracing::warn!("命令子进程管道未关闭，按空输出收尾（pid {pid}）");
                    Ok((Vec::new(), true))
                }
            }
        }
    }
}

/// 终止整个进程组（Unix）；非 Unix 退化为无操作，由 `child.kill()` 兜底。
fn kill_process_group(pid: i32) {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn kill(pid: std::os::raw::c_int, sig: std::os::raw::c_int) -> std::os::raw::c_int;
        }
        const SIGKILL: std::os::raw::c_int = 9;
        // SAFETY：`kill` 为纯系统调用包装；负 pid 表示进程组，无指针解引用。
        let _ = unsafe { kill(-pid, SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
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
                "local",
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
                "local",
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
                "local",
                Path::new("/usr/bin/yes"),
                &args(&["y"]),
                Duration::from_millis(150),
            )
            .unwrap();
        assert!(out.truncated);
        assert!(out.stdout.len() <= 1024);
    }

    #[test]
    fn timeout_kills_grandchildren_holding_pipes() {
        // 后台孙进程继承 stdout：若只 kill 直接子进程，reader 会永久阻塞。
        let start = Instant::now();
        let out = local()
            .run_blocking(
                "local",
                Path::new("/bin/sh"),
                &args(&["-c", "sleep 30 & echo started"]),
                Duration::from_millis(150),
            )
            .unwrap();
        // 直接子进程已退出，但孙进程仍持有管道：调用须在宽限内收尾而非永久阻塞。
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "孙进程持有管道时不得阻塞调用: {:?}",
            start.elapsed()
        );
        assert!(
            out.stdout.contains("started") || out.stdout.is_empty(),
            "输出须为已读内容或空: {:?}",
            out.stdout
        );
    }

    #[test]
    fn nonzero_exit_is_reported() {
        let out = local()
            .run_blocking(
                "local",
                Path::new("/bin/false"),
                &[],
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(out.exit_code, Some(1));
        assert!(!out.success());
        assert!(!out.timed_out);
    }
}
