//! 二进制入口：配置 fail-closed 校验 → sqlite 初始化 → 单 serve 启动。

use {
    std::{process::ExitCode, sync::Arc},
    veil::{
        config::{Config, KeepassBackendKind, resolve_kdbx},
        keepass::{RealKeePass, tpm_password_provider_with_cache},
        router::build_router,
        service::{
            audit::AuditPolicy,
            metrics::METRICS_FLUSH_INTERVAL_SECS,
            tpm::{allow_mock_from_env, startup_tpm_in},
        },
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

/// RUN-1/D1：关闭刷盘——优雅关闭后执行一次最终刷盘（短超时避免拖住退出）；
/// 超时/失败仅 warn，不影响退出码。
async fn flush_on_shutdown(store: Arc<veil::service::metrics::MetricsStore>) -> bool {
    match tokio::time::timeout(std::time::Duration::from_secs(5), store.flush()).await {
        Ok(Ok(())) => {
            tracing::info!("关闭刷盘完成");
            true
        }
        Ok(Err(err)) => {
            tracing::warn!("关闭刷盘失败（已周期刷盘的窗口仍在）: {err:#}");
            false
        }
        Err(_) => {
            tracing::warn!("关闭刷盘超时（5s），跳过最终刷盘");
            false
        }
    }
}

/// RUN-1/D1：`SIGINT`/`SIGTERM` 优雅关闭信号，首个到达即触发。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::warn!("SIGTERM 监听注册失败: {err}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    lock_memory_linux();
    let mut config = match Config::from_env() {
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

    // `POL-1`/D1：启动期 fail-fast 加载审计策略并注入（早于 TPM/sqlite/后台任务等副作用点）；
    // 损坏策略拒启动，不降级为默认空策略。
    let audit_policy = match AuditPolicy::load_startup(config.audit_policy_file.as_deref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };
    // `POL-2`/D2：合并 env 显式与文件 `mode`，把最终生效模式写回运行时配置。
    audit_policy.apply_effective_mode(&mut config);
    // `POL-9`/D9：空白名单门禁按合并后的最终生效模式判定（含文件来源 `approve`），
    // 在策略加载/模式解析之后、副作用点之前拒绝启动。
    if let Err(err) =
        veil::config::validate_approve_whitelist(config.audit_mode, &config.approval_whitelist)
    {
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
    state = state.with_audit_policy(Arc::new(audit_policy));
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
        let (provider, password_cache) =
            tpm_password_provider_with_cache(state.config.tpm_dir.clone(), allow_mock_tpm);
        state = state.with_keepass(Arc::new(
            RealKeePass::new(db_path, keyfile_path, provider)
                .with_master_password_cache(password_cache),
        ));
    } else {
        tracing::warn!("VEIL_KEEPASS_BACKEND=mock：以 Mock KeePass 运行，禁止生产使用");
        state = state.with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    }
    let _orphan_sweeper = state.approval.spawn_sweeper();
    let _pending_sweeper = state.pending.spawn_sweeper();
    state.notify.start();
    // RUN-1/D1：指标周期刷盘驱动（60s）+ 关闭时最终刷盘；当前此二路径是 flush 的唯一生产调用点。
    let _metrics_flush = state
        .admin
        .metrics
        .spawn_flush_driver(std::time::Duration::from_secs(METRICS_FLUSH_INTERVAL_SECS));
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
    let app = build_router(state.clone());
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
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("服务异常退出: {err}");
        return ExitCode::from(1);
    }
    let _ = flush_on_shutdown(state.admin.metrics.clone()).await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{flush_on_shutdown, preflight_whitelist};

    #[tokio::test]
    async fn metrics_flush_on_shutdown() {
        let dir = std::env::temp_dir().join(format!("veil-shutdown-flush-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let db = dir.join("metrics.sqlite");
        let _ = std::fs::remove_file(&db);
        let store = std::sync::Arc::new(veil::service::metrics::MetricsStore::new(db.clone()));
        store.record_aux_counts(veil::service::llm_gateway::Protocol::Chat, 86_400, 0, 0, 1);
        assert!(flush_on_shutdown(store.clone()).await, "关闭刷盘须成功");
        let pts = store.query_series("daily", None, None).await.unwrap();
        assert!(!pts.is_empty(), "关闭刷盘后 sqlite 须含窗口");
        let _ = std::fs::remove_file(&db);
    }

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
        let policy_load = src
            .find("AuditPolicy::load_startup(")
            .expect("策略 fail-fast 加载调用点");
        assert!(
            gate < policy_load,
            "策略加载须在白名单门禁之后（启动序：配置 → 白名单 → 策略）"
        );
        for after in [
            "startup_tpm_in(&config.tpm_dir",
            "init_sqlite(&config.data_dir)",
            ".spawn_sweeper()",
        ] {
            let at = src
                .find(after)
                .unwrap_or_else(|| panic!("缺少启动点 {after}"));
            assert!(gate < at, "白名单门禁须早于 {after}");
            assert!(policy_load < at, "策略加载须早于副作用点 {after}");
        }
    }
}
