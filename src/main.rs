//! 二进制入口：配置 fail-closed 校验 → sqlite 初始化 → 单 serve 启动。

use {
    std::{process::ExitCode, sync::Arc},
    veil::{
        config::{Config, KeepassBackendKind, resolve_kdbx},
        keepass::{RealKeePass, tpm_password_provider},
        router::build_router,
        service::tpm::startup_tpm,
        state::{AppState, init_sqlite},
    },
};

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("启动失败: {err}");
            return ExitCode::from(1);
        }
    };

    let allow_mock_tpm = std::env::var("VEIL_ALLOW_MOCK_TPM").is_ok_and(|v| v.trim() == "1");
    match startup_tpm(allow_mock_tpm) {
        Ok(sealed) => {
            tracing::info!("TPM 门禁通过（密封 {} 字节，明文已弃置）", sealed.len());
            drop(sealed);
        }
        Err(err) => {
            eprintln!("启动失败: TPM 门禁未通过: {err:#}");
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
