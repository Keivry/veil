//! 二进制入口：配置 fail-closed 校验 → sqlite 初始化 → 主监听 + 专用 LLM 监听启动。

use {
    detect_container::is_container,
    std::{process::ExitCode, sync::Arc},
    veil::{
        config::{Config, KeepassBackendKind, resolve_kdbx},
        keepass::{RealKeePass, tpm_password_provider_with_cache},
        logging,
        router::build_router,
        service::{
            admin::ADMIN_RATE_SWEEP_SECS,
            audit::AuditPolicy,
            metrics::METRICS_FLUSH_INTERVAL_SECS,
            request_log::FLUSH_INTERVAL_SECS,
            tpm::{
                TPM_HEALTH_REFRESH_SECS,
                TpmHealth,
                TpmHealthCache,
                allow_mock_from_env,
                startup_tpm_in,
            },
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
        tracing::warn!(
            "警告: mlockall 失败（{}），内存可能被换出，生产建议授予 CAP_IPC_LOCK",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_memory_linux() {}

/// 启动前显式白名单门禁（第一真源为 `Config::load_from` 的配置加载期校验）；
/// 纯校验零副作用，置于 TPM/sqlite/KeePass/后台任务之前，非法白名单 fail-fast。
fn preflight_whitelist(whitelist: &[String]) -> Result<(), String> {
    veil::service::matrix::validate_whitelist_mxids(whitelist)
}

/// 关闭刷盘——优雅关闭后执行一次最终刷盘（短超时避免拖住退出）；
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

/// 网关清理回调持有既有 `AppState` 的共享子句柄（`Arc` 克隆），
/// 不再整体克隆/构造第二个 `AppState`。
#[derive(Clone)]
struct CleanupHandles {
    keepass: std::sync::Arc<dyn veil::keepass::KeePassBackend>,
    vault: std::sync::Arc<veil::service::credential_vault::CredentialVault>,
    pending: std::sync::Arc<veil::approval::PendingApprovals>,
    conversation_scope_store:
        Option<std::sync::Arc<veil::service::redaction::ConversationScopeStore>>,
}

impl veil::service::matrix::GatewayCleanup for CleanupHandles {
    fn keepass_unlocked(&self) -> bool { self.keepass.is_unlocked() }

    fn master_password_cached(&self) -> bool { self.keepass.master_password_cached() }

    fn vault_len(&self) -> usize { self.vault.len() }

    fn lock_cleanup(&self) -> veil::service::matrix::LockCleanupReport {
        let vault_cleared = self.vault.clear();
        self.keepass.clear_cache();
        let master_cleared = self.keepass.clear_master_password();
        let pending = self.pending.clear_all();
        let pii_scopes_cleared = self
            .conversation_scope_store
            .as_ref()
            .map(|store| store.clear())
            .unwrap_or(0);
        tracing::info!(
            "lock 清理: 口令缓存 {vault_cleared} 条、内存待审 {pending} 条、KeePass 会话已清、TPM 主密码缓存清 {master_cleared}、PII 会话作用域 {pii_scopes_cleared} 个"
        );
        veil::service::matrix::LockCleanupReport {
            vault_cleared,
            pii_scopes_cleared,
        }
    }

    fn forget_cleanup(&self) -> usize {
        let cleared = self.vault.clear();
        tracing::info!("forget 清理: token 映射 {cleared} 条");
        cleared
    }
}

/// `SIGINT`/`SIGTERM` 优雅关闭信号，首个到达即触发。
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
    logging::init();
    lock_memory_linux();
    let mut config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };

    // 白名单显式门禁前移至 TPM/sqlite/KeePass/清扫/回填之前——
    // 校验失败在触盘/触网/触 TPM 前即退出。
    if let Err(err) = preflight_whitelist(&config.approval_whitelist) {
        eprintln!("启动失败: {err}");
        return ExitCode::from(1);
    }

    // 启动期 fail-fast 加载审计策略并注入（早于 TPM/sqlite/后台任务等副作用点）；
    // 损坏策略拒启动，不降级为默认空策略。
    let audit_policy = match AuditPolicy::load_startup(config.audit_policy_file.as_deref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };
    // 合并 env 显式与文件 `mode`，把最终生效模式写回运行时配置。
    audit_policy.apply_effective_mode(&mut config);
    // 空白名单门禁按合并后的最终生效模式判定（含文件来源 `approve`），
    // 在策略加载/模式解析之后、副作用点之前拒绝启动。
    if let Err(err) =
        veil::config::validate_approve_whitelist(config.audit_mode, &config.approval_whitelist)
    {
        eprintln!("启动失败: {err}");
        return ExitCode::from(1);
    }

    // 可选功能关闭诊断：与安全配置警告同走裸 stderr，不受 RUST_LOG 抑制。
    if !config.matrix_enabled() {
        eprintln!(
            "警告: Matrix 通知/审批功能未启用：缺少 {}",
            config.missing_matrix_keys().join("、")
        );
        // approve 模式叠加 Matrix 关闭：审计审批记录仅本地可见（无 Matrix 通知）。
        if config.audit_mode == veil::config::AuditMode::Approve {
            eprintln!(
                "警告: 审计模式为 approve 且 Matrix 未启用：审批记录仅本地可见（无 Matrix 通知）"
            );
        }
    }
    if let Some(warning) = config.empty_whitelist_warning() {
        eprintln!("{warning}");
    }
    if !config.admin_surface_enabled() && !config.observability_disabled {
        eprintln!("警告: 管理面未启用：缺少 OBSERVABILITY_ADMIN_TOKEN");
    }

    let allow_mock_tpm = allow_mock_from_env();
    // 采样无盐告警生产接线：谓词单点来自 `PiiSamplerConfig::needs_hmac_warn`（非
    // `#[cfg(test)]` 收编）。此处保留裸 stderr 输出、不迁入 tracing 日志层：该安全配置
    // 告警必须不可抑制（`RUST_LOG=off` 也不得静默），与进程终止类诊断同走 stderr。
    if veil::service::metrics::PiiSamplerConfig::from_config(&config).needs_hmac_warn() {
        eprintln!(
            "警告: PII_VALUE_SAMPLE_ENABLED=1 且未设 PII_VALUE_SAMPLE_HMAC_KEY：hash 退化为无盐 SHA256，低熵 PII 可被离线字典枚举，生产必须配置"
        );
    }
    if let Some(msg) = veil::config::entry_mode_notice(config.entry_mode) {
        eprintln!("警告: {msg}");
    }
    // 缺 HMAC 键时会话列留空（不写可被离线字典反查的弱摘要）；属功能降级，走可抑制的 tracing 告警。
    if config.request_log_enabled && config.pii_value_sample_hmac_key.is_none() {
        tracing::warn!(
            "逐请求记录已启用但未设 PII_VALUE_SAMPLE_HMAC_KEY：/_admin/requests 的会话列将留空（不写入可被字典反查的弱摘要）"
        );
    }
    // 极短授权窗口是可跑但高摩擦的误配：每轮取用都建票并阻塞至 300s 超时。
    // 走 tracing（可抑制），与不可抑制的安全降级告警区分。
    if let Some(ttl) = config.authorization_ttl
        && ttl < 60
    {
        tracing::warn!(
            "[storage].authorization_ttl_secs = {ttl}（< 60s）：授权窗口极短，每次到期都会重建成审批票，无人值守脚本将频繁阻塞至 300s 超时"
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
    // 启动门禁已确认密封材料在位，故初始快照为可用；此后由刷新任务跟踪运行期变化。
    // Mock 模式无真实设备可探，恒报可用且不启动刷新（避免每 60s 空探测）。
    let tpm_health = if allow_mock_tpm {
        std::sync::Arc::new(TpmHealthCache::mock())
    } else {
        let cache = std::sync::Arc::new(TpmHealthCache::new(
            config.tpm_dir.clone(),
            TpmHealth {
                ok: true,
                error: None,
            },
        ));
        cache.spawn_refresher(std::time::Duration::from_secs(TPM_HEALTH_REFRESH_SECS));
        cache
    };

    let outcome = match init_sqlite(&config.data_dir).await {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };
    if !outcome.sqlite_ok {
        tracing::warn!(
            "sqlite 降级内存-only: {}",
            outcome.sqlite_error.as_deref().unwrap_or("未知")
        );
    }

    let mut state = AppState::new(config, outcome);
    state = state.with_audit_policy(Arc::new(audit_policy));
    state = state.with_tpm_health(tpm_health);
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
    // 指标周期刷盘驱动（60s）+ 关闭时最终刷盘；当前此二路径是 flush 的唯一生产调用点。
    let _metrics_flush = state
        .admin
        .metrics
        .spawn_flush_driver(std::time::Duration::from_secs(METRICS_FLUSH_INTERVAL_SECS));
    // 请求日志刷盘驱动（2s 或积压 ≥64 行；design §3）；关闭路径另由 `flush_blocking` 兜底。
    let _request_log_flush = state
        .request_log
        .spawn_flush_driver(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS));
    // 管理面限流周期清扫生产接线（与容量驱逐共同构成有界策略）。
    let _admin_rate_sweep = state
        .admin
        .spawn_rate_sweeper(std::time::Duration::from_secs(ADMIN_RATE_SWEEP_SECS));
    // 指标重启回填：sqlite 聚合覆盖式恢复内存窗口；失败仅 warn（内存-only 照常服务）。
    match state.admin.metrics.backfill_from_sqlite().await {
        Ok(n) => tracing::info!("指标回填完成: {n} 个聚合窗口"),
        Err(err) => tracing::warn!("指标回填失败，内存窗口从空累计: {err:#}"),
    }
    let _matrix_sync = state.config.matrix_enabled().then(|| {
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
            std::sync::Arc::new(CleanupHandles {
                keepass: state.keepass.clone(),
                vault: state.vault.clone(),
                pending: state.pending.clone(),
                conversation_scope_store: state.conversation_scope_store.clone(),
            });
        sync_bot.spawn_sync_loop(
            std::sync::Arc::clone(&state.approval),
            gateway_cleanup,
            sync_token_file,
            start_ts_ms,
        )
    });
    let app = build_router(state.clone());
    let bind_addr = state.config.server_bind;
    let is_loopback = bind_addr.ip().is_loopback();
    let is_container = is_container();
    if !is_loopback && !is_container {
        tracing::warn!(
            "监听地址 {bind_addr} 非回环：该网卡上所有可达方均可访问本服务；\
             容器内需 0.0.0.0:8877，宿主机侧请仅发布到 127.0.0.1"
        );
    }
    if is_loopback && is_container {
        // 容器内监听回环时，bridge 网络的 DNAT 目标不是 lo，宿主发布端口会被 reset；
        // 而 HEALTHCHECK 在容器内跑，仍报 healthy —— 这是"绿但不可达"的经典假象。
        tracing::warn!(
            "检测到容器环境但监听地址为回环 {bind_addr}：端口发布（DNAT）无法投递到回环，\
             宿主机侧将无法访问（容器内 /health 仍为 ok）。请在挂载的 TOML 中设置 \
             [server].bind = \"0.0.0.0:8877\""
        );
    }
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("启动失败: 端口绑定失败: {err}");
            return ExitCode::from(1);
        }
    };
    // 关闭广播：主监听与全部专用监听共用同一次信号（`watch` 保序、可多接收者）。
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tracing::info!("主监听 {bind_addr}（凭据 API + LLM 代理，按 Host 头选路）");
    let mut serves = vec![tokio::spawn(serve_listener(
        listener,
        app.clone(),
        shutdown_rx.clone(),
        format!("主监听 {bind_addr}（凭据 API + LLM 代理）"),
    ))];
    // 专用 LLM 监听：每个已声明端口一条，绑定失败仅告警并继续（其余入口不受影响）。
    for addr in state.config.dedicated_listener_addrs() {
        let upstream = veil::service::llm_gateway::resolve_target(&state.config, Some(addr.port()))
            .map(|target| target.base_url.to_string())
            .unwrap_or_else(|| "（未解析到上游）".to_string());
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                tracing::info!("LLM 入口监听 {addr} → 上游 {upstream}");
                serves.push(tokio::spawn(serve_listener(
                    listener,
                    veil::router::with_ingress_port(app.clone(), addr.port()),
                    shutdown_rx.clone(),
                    format!("LLM 入口 {addr} → {upstream}"),
                )));
            }
            Err(err) => {
                tracing::warn!(
                    "LLM 入口监听 {addr}（上游 {upstream}）绑定失败: {err}；\
                     该端口的 LLM 入口不可用，其余入口不受影响"
                );
            }
        }
    }
    drop(shutdown_rx);
    tracing::info!("已启动 {} 条监听（主监听 {bind_addr}）", serves.len());
    shutdown_signal().await;
    let _ = shutdown_tx.send(true);
    let serve_failed = join_listeners_bounded(serves, SHUTDOWN_JOIN_TIMEOUT).await;
    let _ = flush_on_shutdown(state.admin.metrics.clone()).await;
    // 请求日志同步兜底刷盘：排空队列写库 + 保留期清理，避免 2s 窗口内未落盘的行丢失。
    if let Err(err) = state.request_log.flush_blocking() {
        tracing::warn!("请求日志关闭刷盘失败（已周期落盘的行不受影响）: {err:#}");
    }
    // 优雅停机——abort 通知消费者（剩余队列 best-effort 丢弃）。
    state.notify.shutdown();
    if serve_failed {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// 关闭时等待全部监听退出的上限。
///
/// 必须设上限：Axum 的优雅关闭会等在途连接自然结束，而 `/_admin/events/stream`
/// 的 SSE 与长 LLM 流不会自行结束，无限等待会让 SIGTERM 永久挂住、后续刷盘与
/// `notify.shutdown()` 永不执行（监听越多越容易）。超时即继续清理，宁可放弃
/// 未退出的监听也不丢已排队的数据。
const SHUTDOWN_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 在 `timeout` 内收敛全部 serve 任务，返回是否有任务失败。
///
/// 超时后仍返回已观测到的失败标记并交由调用方继续清理；未退出的任务被 detach
/// （不 abort，避免截断已在写响应的连接）。
async fn join_listeners_bounded(
    serves: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
    timeout: std::time::Duration,
) -> bool {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let total = serves.len();
    let stopped = Arc::new(AtomicUsize::new(0));
    let serve_failed = Arc::new(AtomicBool::new(false));
    let drain = {
        let stopped = Arc::clone(&stopped);
        let serve_failed = Arc::clone(&serve_failed);
        async move {
            for handle in serves {
                match handle.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        eprintln!("服务异常退出: {err}");
                        serve_failed.store(true, Ordering::SeqCst);
                    }
                    Err(err) => {
                        eprintln!("服务监听任务异常: {err}");
                        serve_failed.store(true, Ordering::SeqCst);
                    }
                }
                stopped.fetch_add(1, Ordering::SeqCst);
            }
        }
    };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        tracing::warn!(
            "关闭超时（{timeout:?}）：{}/{} 条监听未停止\
             （SSE / 长 LLM 流可能仍在传输），继续执行刷盘与停机通知",
            total.saturating_sub(stopped.load(Ordering::SeqCst)),
            total
        );
    }
    serve_failed.load(Ordering::SeqCst)
}

/// 单监听 serve：收到关闭信号后优雅停止（在途请求处理完毕），返回 `serve` 结果。
async fn serve_listener(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    label: String,
) -> std::io::Result<()> {
    if *shutdown.borrow() {
        return Ok(());
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown.wait_for(|stop| *stop).await;
        tracing::info!("{label} 停止接收新请求");
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::{flush_on_shutdown, join_listeners_bounded, preflight_whitelist};

    #[test]
    fn shutdown_wired() {
        // 多监听停机：信号驱动一次广播 → 有界收敛（超时也不阻塞后续清理）→
        // 清理（刷盘/notify.shutdown）恰一次且在所有监听停止之后。
        let src = include_str!("main.rs");
        let signal = src
            .find("shutdown_signal().await")
            .expect("优雅关闭信号等待点");
        let broadcast = src.find("shutdown_tx.send(true)").expect("关闭广播发送点");
        let join = src
            .find("join_listeners_bounded(serves, SHUTDOWN_JOIN_TIMEOUT).await")
            .expect("监听任务收敛点");
        let flush = src
            .find("flush_on_shutdown(state.admin.metrics.clone())")
            .expect("关闭刷盘点");
        let shutdown = src
            .find("state.notify.shutdown()")
            .expect("notify.shutdown 接线点");
        assert!(signal < broadcast, "关闭广播须在信号之后");
        assert!(broadcast < join, "监听收敛须在广播之后");
        assert!(join < flush, "关闭刷盘须在所有监听停止之后");
        assert!(flush < shutdown, "停机通知须在刷盘之后");
        // 收敛必须有界：SSE / 长 LLM 流不自行结束，无超时会永久挂住关闭路径。
        let bounded = src
            .find("tokio::time::timeout(timeout, drain)")
            .expect("监听收敛须带超时上限");
        assert!(join < bounded, "超时包装须位于收敛点之后");
        assert!(
            src.contains("const SHUTDOWN_JOIN_TIMEOUT: std::time::Duration"),
            "关闭收敛超时须为具名常量"
        );
        assert!(
            src.contains("条监听未停止"),
            "超时须 warn 报告未停止的监听数"
        );
        let production = src
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("生产段须存在");
        assert_eq!(
            production.matches("state.notify.shutdown()").count(),
            1,
            "停机通知须恰触发一次"
        );
        assert_eq!(
            production
                .matches("flush_on_shutdown(state.admin.metrics.clone())")
                .count(),
            1,
            "关闭刷盘须恰触发一次"
        );
        assert!(
            src.contains("tokio::spawn(serve_listener("),
            "每条监听须独立 spawn 同一 serve 封装"
        );
        assert!(
            src.contains(".with_graceful_shutdown("),
            "serve 须接到优雅关闭信号"
        );
        let banned = format!("Arc::new(state{})", ".clone())");
        assert!(
            !src.contains(&banned),
            "GatewayCleanup 不得构造第二个 AppState"
        );
        assert!(
            src.contains("CleanupHandles"),
            "清理须复用既有 AppState 的共享子句柄"
        );
    }

    /// 无上限收敛会永久挂住：一个永不结束的任务（模拟 SSE / 长 LLM 流）必须在
    /// 超时后放弃并返回，不阻塞调用方继续清理。
    #[tokio::test]
    async fn join_listeners_bounded_times_out_on_hung_listener() {
        let hung = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let done = tokio::spawn(async { Ok(()) });
        let started = std::time::Instant::now();
        let failed =
            join_listeners_bounded(vec![done, hung], std::time::Duration::from_millis(50)).await;
        assert!(!failed, "无失败任务时不得置退出码");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "超时须有界返回，实际 {:?}",
            started.elapsed()
        );
    }

    /// 失败标记须保留：serve 任务返回错误即令退出码为 1，即使同时存在未退出任务。
    #[tokio::test]
    async fn join_listeners_bounded_keeps_failure_flag() {
        let failed_serve =
            tokio::spawn(async { Err(std::io::Error::other("模拟 serve 异常退出")) });
        let hung = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        assert!(
            join_listeners_bounded(
                vec![failed_serve, hung],
                std::time::Duration::from_millis(50)
            )
            .await,
            "任一 serve 失败须令退出码为 1"
        );
    }

    #[tokio::test]
    async fn metrics_flush_on_shutdown() {
        let dir = std::env::temp_dir().join(format!("veil-shutdown-flush-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let db = dir.join("metrics.sqlite");
        let _ = std::fs::remove_file(&db);
        let store = std::sync::Arc::new(veil::service::metrics::MetricsStore::new(db.clone()));
        store.record_aux_counts_extended(
            veil::service::llm_gateway::Protocol::Chat,
            86_400,
            7,
            4,
            3,
            1,
        );
        assert!(flush_on_shutdown(store.clone()).await, "关闭刷盘须成功");
        let pts = store.query_series("daily", None, None).await.unwrap();
        assert!(!pts.is_empty(), "关闭刷盘后 sqlite 须含窗口");
        let _ = std::fs::remove_file(&db);
    }

    /// 真实门禁函数行为（非法拒绝/合法放行）+ 生产启动序不变量——门禁调用须早于
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
