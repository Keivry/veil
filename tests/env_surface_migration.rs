//! 进程 env 边界收敛 + 必需性反转的 spawn 测试。
//!
//! edition-2024 下 `std::env::set_var` 为 `unsafe` 且并行测试互污，进程 env 测试
//! 只能置于集成层：经 `env!("CARGO_BIN_EXE_veil")` 定位二进制，`env_clear` 后只注入
//! 白名单 env（密钥类）与 `VEIL_CONFIG_FILE`，把已迁移的部署参数写入临时 TOML。
//!
//! 覆盖两类语义：
//! - 迁移项（进程 env 面已关闭）：置位仅告警、不生效、不拒启动；
//! - 可选功能（Matrix 三要素 / admin token）：缺失即关闭功能、不拒启动，且启动期 `eprintln!`
//!   指名缺失键（与安全配置告警同走裸 stderr，不受 `RUST_LOG` 抑制）。
//!
//! 日志流：`src/logging.rs` 显式 `.with_writer(std::io::stderr)`，故断言 stderr。
//! 全部用例共享硬编码监听端口 8877，用静态锁串行化；端口被外部占用时按「端口绑定
//! 失败」容忍，不挂起。

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_veil");
const MATRIX_TOKEN: &str = "syt_matrix_token_xxx";
const ADMIN_TOKEN: &str = "admin-observability-token-0123456789abcdef";

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 每用例独立临时目录；`Drop` 整目录清理（含临时 TOML 与数据目录）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "veil-env-surface-spawn-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("建临时目录");
        Self { path }
    }

    /// 可写数据目录（`[storage].data_dir` 指向它，避免落到不可写的默认 `/data`）。
    fn data_dir(&self) -> PathBuf {
        let dir = self.path.join("data");
        std::fs::create_dir_all(&dir).expect("建临时数据目录");
        dir
    }

    fn write_config(&self, body: &str) -> PathBuf {
        let path = self.path.join("veil.toml");
        std::fs::write(&path, body).expect("写临时 TOML");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.path).ok(); }
}

fn toml_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// 最小 TOML：`[storage].data_dir` 恒有；`[matrix]` 仅在 `matrix` 非空时写出。
fn config_toml(data_dir: &Path, matrix: &[(&str, &str)]) -> String {
    let mut out = String::from("[storage]\n");
    out.push_str(&format!("data_dir = \"{}\"\n", toml_escape(data_dir)));
    if !matrix.is_empty() {
        out.push_str("\n[matrix]\n");
        for (key, value) in matrix {
            out.push_str(&format!("{key} = \"{value}\"\n"));
        }
    }
    out
}

/// 最小启动命令：引导变量 + Mock TPM；清空继承环境，密钥 token 由各场景按需补。
fn base_cmd(config_file: &Path) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("VEIL_CONFIG_FILE", config_file)
        .env("VEIL_ALLOW_MOCK_TPM", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

/// 启动子进程、收集 stderr，并在 `grace` 内判定其是否曾处于运行态（随后 Kill）。
fn run_and_collect(mut cmd: Command, grace: Duration) -> (String, bool) {
    let mut child = cmd.spawn().expect("启动 veil 二进制");
    let mut stderr = child.stderr.take().expect("stderr 管道");
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });
    let deadline = Instant::now() + grace;
    let mut started = false;
    while Instant::now() < deadline {
        match child.try_wait().expect("try_wait") {
            None => started = true,
            Some(_) => break,
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    (reader.join().unwrap_or_default(), started)
}

/// 断言进程未因配置性错误拒启动：要么在 grace 内存活，要么仅因端口占用退出。
fn assert_started_or_port_conflict(stderr: &str, started: bool) {
    if !started {
        assert!(
            stderr.contains("端口绑定失败"),
            "进程未存活且非端口占用，须视为配置性拒启动: {stderr}"
        );
    }
}

/// 已迁移的致命 env 被忽略：进程不因它们拒启动；迁移清单内的名字告警，
/// 0.2.0 改名前的旧名（自本版起无任何告警）完全静默。
#[test]
fn migrated_fatal_env_ignored_and_warns() {
    let _guard = serial_lock();
    let tmp = TempDir::new("negative");
    let cfg = tmp.write_config(&config_toml(
        &tmp.data_dir(),
        &[
            ("homeserver", "https://matrix.example.com"),
            ("room_id", "!room:example.com"),
        ],
    ));
    let mut cmd = base_cmd(&cfg);
    cmd.env("MATRIX_ACCESS_TOKEN", MATRIX_TOKEN)
        .env("OBSERVABILITY_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("AUDIT_TIMEOUT", "120")
        .env("AUDIT_MODE", "bogus");
    let (stderr, started) = run_and_collect(cmd, Duration::from_secs(2));

    // 决定性否定：若仍读取，审计超时落在 110-130 禁区会拒启动、
    // `AUDIT_MODE=bogus` 解析失败。
    assert!(
        !stderr.contains("不得落在"),
        "审计超时旧名仍被读取（应已迁移）: {stderr}"
    );
    assert!(
        !stderr.contains("AUDIT_MODE 非法"),
        "AUDIT_MODE 仍被读取（应已迁移）: {stderr}"
    );
    // 迁移清单名（AUDIT_MODE）仍告警；改名旧名已无任何提示。
    assert!(
        stderr.contains("AUDIT_MODE") && stderr.contains("VEIL_CONFIG_FILE"),
        "stderr 须含迁移告警与 VEIL_CONFIG_FILE 指引: {stderr}"
    );
    assert!(
        !stderr.contains("AUDIT_TIMEOUT"),
        "改名旧名置位不得产生任何提示: {stderr}"
    );
    assert_started_or_port_conflict(&stderr, started);
}

/// 已迁移的 `LLM_UPSTREAM` 进程 env 被忽略：仅告警、不启用上游、进程仍启动。
#[test]
fn migrated_llm_upstream_env_ignored_and_warns() {
    let _guard = serial_lock();
    let tmp = TempDir::new("llm-upstream");
    let cfg = tmp.write_config(&config_toml(
        &tmp.data_dir(),
        &[
            ("homeserver", "https://matrix.example.com"),
            ("room_id", "!room:example.com"),
        ],
    ));
    let mut cmd = base_cmd(&cfg);
    cmd.env("MATRIX_ACCESS_TOKEN", MATRIX_TOKEN)
        .env("OBSERVABILITY_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("LLM_UPSTREAM", "http://127.0.0.1:11434");
    let (stderr, started) = run_and_collect(cmd, Duration::from_secs(2));

    assert!(
        stderr.contains("LLM_UPSTREAM 不再从进程 env 读取"),
        "已迁移的 LLM_UPSTREAM 置位须被告警并忽略: {stderr}"
    );
    assert!(
        stderr.contains("VEIL_CONFIG_FILE"),
        "迁移告警须含 VEIL_CONFIG_FILE 指引: {stderr}"
    );
    assert_started_or_port_conflict(&stderr, started);
}

/// 四个可选键处处缺失：进程启动成功，Matrix 告警指名三键、管理面告警指名 admin token。
#[test]
fn all_optional_keys_missing_starts_with_named_warnings() {
    let _guard = serial_lock();
    let tmp = TempDir::new("all-missing");
    let cfg = tmp.write_config(&config_toml(&tmp.data_dir(), &[]));
    let cmd = base_cmd(&cfg);
    let (stderr, started) = run_and_collect(cmd, Duration::from_secs(2));

    assert!(
        stderr.contains("警告: Matrix 通知/审批功能未启用：缺少"),
        "缺 Matrix 三要素须给出启动期告警: {stderr}"
    );
    for key in ["HOMESERVER", "ROOM_ID", "MATRIX_ACCESS_TOKEN"] {
        assert!(
            stderr.contains(key),
            "Matrix 告警须指名缺失键 {key}: {stderr}"
        );
    }
    assert!(
        stderr.contains("警告: 管理面未启用：缺少 OBSERVABILITY_ADMIN_TOKEN"),
        "缺 admin token 须给出启动期告警: {stderr}"
    );
    assert_started_or_port_conflict(&stderr, started);
}

/// 仅 `ROOM_ID` 缺失：进程启动成功，Matrix 告警仅指名该键。
#[test]
fn partial_matrix_keys_missing_warns_only_named_key() {
    let _guard = serial_lock();
    let tmp = TempDir::new("partial");
    let cfg = tmp.write_config(&config_toml(
        &tmp.data_dir(),
        &[("homeserver", "https://matrix.example.com")],
    ));
    let mut cmd = base_cmd(&cfg);
    cmd.env("MATRIX_ACCESS_TOKEN", MATRIX_TOKEN)
        .env("OBSERVABILITY_ADMIN_TOKEN", ADMIN_TOKEN);
    let (stderr, started) = run_and_collect(cmd, Duration::from_secs(2));

    assert!(
        stderr.contains("警告: Matrix 通知/审批功能未启用：缺少 ROOM_ID"),
        "Matrix 告警须指名唯一缺失键 ROOM_ID: {stderr}"
    );
    assert!(
        !stderr.contains("缺少 HOMESERVER"),
        "仅 ROOM_ID 缺失时不得把 HOMESERVER 列为缺失: {stderr}"
    );
    assert_started_or_port_conflict(&stderr, started);
}

/// 仅进程 env 设 `HOMESERVER`（文件无）：值不生效、仅告警，进程仍启动。
#[test]
fn env_only_homeserver_ignored_and_warns() {
    let _guard = serial_lock();
    let tmp = TempDir::new("env-only");
    let cfg = tmp.write_config(&config_toml(
        &tmp.data_dir(),
        &[("room_id", "!room:example.com")],
    ));
    let mut cmd = base_cmd(&cfg);
    cmd.env("MATRIX_ACCESS_TOKEN", MATRIX_TOKEN)
        .env("OBSERVABILITY_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("HOMESERVER", "https://env-only.example.com");
    let (stderr, started) = run_and_collect(cmd, Duration::from_secs(2));

    assert!(
        stderr.contains("HOMESERVER 不再从进程 env 读取"),
        "进程 env HOMESERVER 须被告警并忽略: {stderr}"
    );
    assert!(
        stderr.contains("VEIL_CONFIG_FILE"),
        "迁移告警须含 VEIL_CONFIG_FILE 指引: {stderr}"
    );
    assert!(
        stderr.contains("警告: Matrix 通知/审批功能未启用：缺少 HOMESERVER"),
        "env HOMESERVER 不生效后 Matrix 须按关闭处理并指名: {stderr}"
    );
    assert_started_or_port_conflict(&stderr, started);
}

/// approve 模式 + Matrix 关闭：允许启动，且启动期 warn 说明审批记录仅本地可见。
#[test]
fn approve_mode_without_matrix_warns_local_only() {
    let _guard = serial_lock();
    let tmp = TempDir::new("approve-matrix-off");
    let mut body = config_toml(&tmp.data_dir(), &[]);
    body.push_str("\n[audit]\nmode = \"approve\"\napproval_whitelist = [\"@admin:example.com\"]\n");
    let cfg = tmp.write_config(&body);
    let (stderr, started) = run_and_collect(base_cmd(&cfg), Duration::from_secs(2));

    assert!(
        stderr.contains("审批记录仅本地可见"),
        "approve + Matrix 关闭须说明审批记录仅本地可见: {stderr}"
    );
    assert_started_or_port_conflict(&stderr, started);
}
