//! 二进制入口：配置 fail-closed 校验 → sqlite 初始化 → 单 serve 启动。

use {
    std::{process::ExitCode, sync::Arc},
    veil::{
        config::{Config, KeepassBackendKind, resolve_kdbx},
        keepass::{RealKeePass, tpm_password_provider},
        router::build_router,
        service::tpm::{allow_mock_from_env, startup_tpm_in},
        state::{AppState, init_sqlite},
    },
};

/// Linux 内存锁定：`mlockall(MCL_CURRENT | MCL_FUTURE)` 把已映射与未来映射的
/// 内存全部锁入 RAM，防止密钥/口令被换出到 swap。失败仅 warn 不拒启动
/// （容器缺 `CAP_IPC_LOCK` 时常见，网关仍可运行；生产建议补该 capability）。
/// 非 Linux 平台直接跳过（无对应语义）。实现上直连 libc 符号，不引入新依赖。
#[cfg(target_os = "linux")]
fn lock_memory_linux() {
    unsafe extern "C" {
        fn mlockall(flags: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    const MCL_CURRENT: std::os::raw::c_int = 1;
    const MCL_FUTURE: std::os::raw::c_int = 2;
    // SAFETY：`mlockall` 为纯 C 库调用，参数仅为标志位，无内存安全前置条件；
    // 返回值检查后转 `last_os_error`，不解引用任何指针。
    let rc = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
    if rc != 0 {
        eprintln!(
            "警告: mlockall 失败（{}），内存可能被换出，生产建议授予 CAP_IPC_LOCK",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_memory_linux() {}

/// A15/D14：启动前显式白名单门禁（第一真源为 `Config::load_from` 的配置加载期校验）；
/// 纯校验零副作用，置于 TPM/sqlite/KeePass/后台任务之前，非法白名单 fail-fast。
fn preflight_whitelist(whitelist: &[String]) -> Result<(), String> {
    veil::service::matrix::validate_whitelist_mxids(whitelist)
}

#[tokio::main]
async fn main() -> ExitCode {
    lock_memory_linux();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };

    // A15/D14：白名单显式门禁前移至 TPM/sqlite/KeePass/清扫/回填之前——
    // 校验失败在触盘/触网/触 TPM 前即退出。
    if let Err(err) = preflight_whitelist(&config.approval_whitelist) {
        eprintln!("启动失败: {err}");
        return ExitCode::from(1);
    }

    let allow_mock_tpm = allow_mock_from_env();
    if config.pii_value_sample_enabled
        && config
            .pii_value_sample_hmac_key
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        tracing::warn!(
            "PII_VALUE_SAMPLE_ENABLED=1 且未设 PII_VALUE_SAMPLE_HMAC_KEY：hash 退化为无盐 SHA256，低熵 PII 可被离线字典枚举，生产必须配置"
        );
    }
    match startup_tpm_in(&config.tpm_dir, allow_mock_tpm) {
        Ok(sealed) => {
            tracing::info!("TPM 门禁通过（密封 {} 字节，明文已弃置）", sealed.len());
            drop(sealed);
        }
        Err(err) => {
            eprintln!("启动失败: TPM 门禁未通过: {err:#}");
            eprintln!(
                "无 TPM 硬件的开发机/CI 可设置 VEIL_ALLOW_MOCK_TPM=1 后重试（仅开发/CI，生产禁用）"
            );
            return ExitCode::from(1);
        }
    };

    let outcome = match init_sqlite(&config.data_dir).await {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };
    if !outcome.sqlite_ok {
        eprintln!(
            "sqlite 降级内存-only: {}",
            outcome.sqlite_error.as_deref().unwrap_or("未知")
        );
    }

    let mut state = AppState::new(config, outcome);
    if state.config.keepass_backend == KeepassBackendKind::Real {
        let resolved = resolve_kdbx(&state.config.db_dir);
        let (db_path, keyfile_path) = match &resolved {
            Some(found) => (found.db_path.clone(), found.keyfile_path.clone()),
            None => {
                tracing::warn!(
                    "DB_DIR 无 .kdbx（{}），凭据接口返回 503 密码库未配置",
                    state.config.db_dir.display()
                );
                (state.config.db_dir.join("veil.kdbx"), None)
            }
        };
        let provider = tpm_password_provider(state.config.tpm_dir.clone(), allow_mock_tpm);
        state = state.with_keepass(Arc::new(RealKeePass::new(db_path, keyfile_path, provider)));
    } else {
        tracing::warn!("VEIL_KEEPASS_BACKEND=mock：以 Mock KeePass 运行，禁止生产使用");
        state = state.with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    }
    let _orphan_sweeper = state.approval.spawn_sweeper();
    let _pending_sweeper = state.pending.spawn_sweeper();
    state.notify.start();
    // 指标重启回填：sqlite 聚合覆盖式恢复内存窗口；失败仅 warn（内存-only 照常服务）。
    match state.admin.metrics.backfill_from_sqlite().await {
        Ok(n) => tracing::info!("指标回填完成: {n} 个聚合窗口"),
        Err(err) => tracing::warn!("指标回填失败，内存窗口从空累计: {err:#}"),
    }
    let sync_bot = veil::service::matrix::MatrixBot::with_client(
        state.config.homeserver.clone(),
        state.config.room_id.clone(),
        state.config.matrix_access_token.clone(),
        (*state.http_client).clone(),
    );
    let sync_token_file = state.config.data_dir.join("sync_token");
    let start_ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let gateway_cleanup: std::sync::Arc<dyn veil::service::matrix::GatewayCleanup> =
        std::sync::Arc::new(state.clone());
    let _matrix_sync = sync_bot.spawn_sync_loop(
        std::sync::Arc::clone(&state.approval),
        gateway_cleanup,
        sync_token_file,
        start_ts_ms,
    );
    let app = build_router(state);
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:8877").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("启动失败: 端口绑定失败: {err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        eprintln!("服务异常退出: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::preflight_whitelist;

    /// A15/D14：真实门禁函数行为（非法拒绝/合法放行）+ 生产启动序不变量——门禁调用须早于
    /// TPM/sqlite/后台任务等副作用点；门禁纯校验零副作用，其失败即 fail-fast，不触盘/触
    /// TPM/起任务。
    #[test]
    fn startup_whitelist_fail_fast() {
        assert!(
            preflight_whitelist(&["@a@b:c".to_string()]).is_err(),
            "非法白名单须拒绝"
        );
        assert!(
            preflight_whitelist(&["@admin:example.com".to_string()]).is_ok(),
            "合法白名单须放行"
        );
        let src = include_str!("main.rs");
        let gate = src
            .find("preflight_whitelist(&config.approval_whitelist)")
            .expect("白名单门禁调用点");
        for after in [
            "startup_tpm_in(&config.tpm_dir",
            "init_sqlite(&config.data_dir)",
            ".spawn_sweeper()",
        ] {
            let at = src
                .find(after)
                .unwrap_or_else(|| panic!("缺少启动点 {after}"));
            assert!(gate < at, "白名单门禁须早于 {after}");
        }
    }
}
