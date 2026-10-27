//! 命令 API 编排：认证 → 授权 → 参数校验 → 审批判定 → 执行。
//!
//! 自动放行（`requires_approval = false`、配置 `auto_approve`、运行时 accept-always）
//! 仅在调用方已注册且哈希匹配时生效；未注册调用方只能按未注册口径转审批，
//! 且审批不绕过 `allow_commands` 与目标范围校验。

use {
    super::{
        ExecutionEntry,
        PendingInvocation,
        execution_record_ttl,
        ticket::{approval_message, command_ticket_parts},
    },
    crate::{
        config::{CommandDef, ParameterKind, command::placeholders},
        error::{Result, VeilError},
        service::{
            command::exec::CommandOutput,
            credential::{
                AuthBlock,
                CredentialBody,
                CredentialHeaders,
                approval::{clear_terminal_pending, submit_pending_with_branch},
                auth::{CallerLookup, effective_caller, resolve_caller},
                ratelimit::check_rate,
            },
        },
    },
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

/// 审批等待上限（秒），与凭据审批同口径。
const APPROVAL_TIMEOUT_SECS: u64 = 300;
/// `params_json` 单值上限（字符），超出即拒绝。
const PARAM_STRING_MAX_CHARS: usize = 4096;

/// `POST /commands/{id}/invoke` 请求体。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InvokeRequest {
    #[serde(default)]
    pub auth: Option<AuthBlock>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub params: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub target: Option<TargetSpec>,
}

/// 目标 host（分组仅用于命令可用范围）。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TargetSpec {
    #[serde(default)]
    pub host: Option<String>,
}

/// 调用结果：待审批或终态。
#[derive(Debug, Clone)]
pub enum InvokeResult {
    Pending {
        message: String,
        approval_event_id: String,
    },
    Terminal(Terminal),
}

/// 终态（同一审批幂等键复用同一结果）。
#[derive(Debug, Clone)]
pub enum Terminal {
    Executed {
        approval_status: String,
        approval_event_id: Option<String>,
        host: String,
        output: CommandOutput,
    },
    Denied {
        approval_status: String,
        approval_event_id: Option<String>,
        message: String,
    },
    ApprovalTimeout {
        approval_event_id: String,
        message: String,
    },
    ExecError {
        approval_status: String,
        approval_event_id: Option<String>,
        message: String,
    },
}

impl Terminal {
    pub fn approval_status(&self) -> &str {
        match self {
            Self::Executed {
                approval_status, ..
            }
            | Self::Denied {
                approval_status, ..
            }
            | Self::ExecError {
                approval_status, ..
            } => approval_status,
            Self::ApprovalTimeout { .. } => "timeout",
        }
    }

    pub fn exec_status(&self) -> &'static str {
        match self {
            Self::Executed { output, .. } => {
                if output.timed_out {
                    "timeout"
                } else if output.exit_code == Some(0) {
                    "executed"
                } else {
                    "failed"
                }
            }
            Self::ExecError { .. } => "failed",
            Self::Denied { .. } | Self::ApprovalTimeout { .. } => "not_run",
        }
    }

    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Executed { output, .. } => output.exit_code,
            _ => None,
        }
    }

    pub fn output(&self) -> Option<&CommandOutput> {
        match self {
            Self::Executed { output, .. } => Some(output),
            _ => None,
        }
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Denied { message, .. }
            | Self::ApprovalTimeout { message, .. }
            | Self::ExecError { message, .. } => Some(message),
            Self::Executed { .. } => None,
        }
    }
}

fn not_found() -> VeilError {
    VeilError::NotFound {
        message: "命令能力未启用".to_string(),
    }
}

fn deny(message: impl Into<String>) -> VeilError {
    VeilError::Auth {
        message: message.into(),
    }
}

/// 调用的有效身份（已通过三因子与注册表门禁）。
struct CallerContext {
    caller_path: String,
    caller_hash: String,
    /// 命中注册条目且启用：自动放行与命令目录的准入依据。
    registered: bool,
    /// 注册表认得该调用方（含哈希变更、按哈希命中）；仅用于票面措辞，
    /// 不参与准入——准入一律看 `registered`。
    known_entry: bool,
}

async fn authenticate(
    state: &impl crate::service::credential::AppStateParts,
    headers: &CredentialHeaders,
    body: &CredentialBody,
) -> Result<CallerContext> {
    crate::service::credential::verify_three_factor_write(state, headers, body).await?;
    let (caller_hash, caller_path) = effective_caller(headers, body);
    let lookup = resolve_caller(state, &caller_path, &caller_hash).await?;
    let known_entry = !matches!(lookup, CallerLookup::Unknown);
    Ok(CallerContext {
        caller_path,
        caller_hash,
        registered: matches!(lookup, CallerLookup::Enrolled { .. }),
        known_entry,
    })
}

/// `GET /commands`：返回调用者可见的命令目录。
pub async fn catalog(
    state: &impl crate::service::credential::AppStateParts,
    headers: &CredentialHeaders,
) -> Result<Value> {
    let runtime = state.command();
    if !runtime.config.enabled {
        return Err(not_found());
    }
    let body = CredentialBody::default();
    let caller = authenticate(state, headers, &body).await?;
    let empty = || json!({"ok": true, "commands": []});
    let Some((_, downstream)) = runtime.config.downstream_for(&caller.caller_path) else {
        return Ok(empty());
    };
    if !caller.registered {
        return Ok(empty());
    }
    let commands: Vec<Value> = runtime
        .config
        .commands
        .iter()
        .filter(|(id, _)| downstream.allows(id))
        .map(|(id, def)| {
            let parameters: serde_json::Map<String, Value> = def
                .parameters
                .iter()
                .map(|(name, parameter)| {
                    let spec = match &parameter.kind {
                        ParameterKind::Enum(values) => json!({"kind": "enum", "values": values}),
                        ParameterKind::Integer => json!({"kind": "integer"}),
                        ParameterKind::String => json!({"kind": "string"}),
                    };
                    (name.clone(), spec)
                })
                .collect();
            let groups: Vec<&String> = runtime
                .config
                .groups
                .keys()
                .filter(|group| def.hosts.iter().any(|scope| scope == *group))
                .collect();
            json!({
                "id": id,
                "description": def.description,
                "usage": def.usage,
                "parameters": parameters,
                "hosts": runtime.config.allowed_hosts(def),
                "groups": groups,
                "requires_approval": def.requires_approval,
            })
        })
        .collect();
    Ok(json!({"ok": true, "commands": commands}))
}

/// `POST /commands/{id}/invoke`。
pub async fn invoke(
    state: &(impl crate::service::credential::AppStateParts + Clone + Send + Sync + 'static),
    headers: &CredentialHeaders,
    command_id: &str,
    request: InvokeRequest,
) -> Result<InvokeResult> {
    let runtime = state.command();
    if !runtime.config.enabled {
        return Err(not_found());
    }
    let body = CredentialBody {
        secret: request.secret.clone(),
        auth: request.auth.clone(),
        ..CredentialBody::default()
    };
    let caller = authenticate(state, headers, &body).await?;

    let Some((downstream_name, downstream)) = runtime.config.downstream_for(&caller.caller_path)
    else {
        return Err(deny("调用方未绑定任何 downstream，拒绝"));
    };
    if !downstream.allows(command_id) {
        return Err(deny("命令不在该下游的 allow_commands 内，拒绝"));
    }
    let Some(def) = runtime.config.commands.get(command_id) else {
        return Err(VeilError::NotFound {
            message: format!("命令 {command_id} 不存在"),
        });
    };
    let host = request
        .target
        .as_ref()
        .and_then(|target| target.host.as_deref())
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| VeilError::BadRequest {
            message: "target.host 必填".to_string(),
        })?
        .to_string();
    if runtime.config.is_group(&host) {
        return Err(VeilError::BadRequest {
            message: format!("target 须为分组 {host} 内的具体 host"),
        });
    }
    if !runtime.config.hosts.contains_key(&host) {
        return Err(deny(format!("目标 host {host} 不存在，拒绝")));
    }
    if !runtime.config.is_host_allowed(def, &host) {
        return Err(deny(format!(
            "目标 host {host} 不在命令 {command_id} 的可用范围内，拒绝"
        )));
    }

    let raw_params = request.params.unwrap_or_default();
    let params = validate_params(def, &raw_params)?;
    let argv = def.render_argv(&params);
    let params_json = serde_json::to_string(&params).unwrap_or_default();
    let key = execution_key(
        &caller.caller_path,
        &caller.caller_hash,
        command_id,
        &host,
        &params_json,
    );

    match runtime.entry(&key) {
        Some(ExecutionEntry::Done(terminal)) => {
            return Ok(InvokeResult::Terminal((*terminal).clone()));
        }
        Some(ExecutionEntry::Pending(pending)) => {
            if let Some(terminal) = drive_pending(state, &key, &pending).await {
                return Ok(InvokeResult::Terminal(terminal));
            }
            return Ok(InvokeResult::Pending {
                message: "命令调用待审批".to_string(),
                approval_event_id: pending.event_id.clone(),
            });
        }
        None => {}
    }

    check_rate(
        &runtime.hits,
        &format!(
            "command:{}:{}:{command_id}:{host}",
            caller.caller_path, caller.caller_hash
        ),
        crate::config::CREDENTIAL_RATE_WINDOW_SECS,
    )
    .await?;

    let static_auto = downstream.auto_allows(command_id, &host, &runtime.config);
    let runtime_grant = runtime
        .grants
        .contains(&caller.caller_path, command_id, &host)
        .await;
    let auto_allowed =
        caller.registered && (!def.requires_approval || static_auto || runtime_grant);
    if auto_allowed {
        let output = run_command(state, &host, &def.program, &argv, def.timeout_secs).await;
        let terminal = terminal_from_output(None, "not_required", &host, output);
        log_terminal(
            state,
            &caller,
            downstream_name,
            command_id,
            &host,
            &params_json,
            &terminal,
        )
        .await;
        return Ok(InvokeResult::Terminal(terminal));
    }

    let parts = command_ticket_parts(command_id, &host, &argv, def.timeout_secs);
    let ctx = approval_message(
        &parts,
        &caller.caller_path,
        Some(downstream_name),
        caller.known_entry,
    );
    let pending_key = format!("command:{key}");
    let event_id = submit_pending_with_branch(state, &pending_key, &ctx).await?;
    let pending = Arc::new(PendingInvocation {
        event_id: event_id.clone(),
        pending_key,
        caller_path: caller.caller_path.clone(),
        caller_hash: caller.caller_hash.clone(),
        downstream: downstream_name.to_string(),
        command_id: command_id.to_string(),
        host: host.clone(),
        program: def.program.clone(),
        argv,
        timeout_secs: def.timeout_secs,
        params_json,
    });
    runtime.set_pending(&key, pending.clone());

    if runtime.config.block_wait {
        let decision = state
            .approval()
            .ask(&event_id, Duration::from_secs(APPROVAL_TIMEOUT_SECS))
            .await;
        let terminal = complete(state, &key, &pending, decision).await;
        return Ok(InvokeResult::Terminal(terminal));
    }

    let owned = (*state).clone();
    let key_owned = key.clone();
    let waiter = pending.clone();
    crate::logging::spawn_in_request_span(async move {
        let decision =
            crate::service::credential::await_credential_approval(&owned, &waiter.event_id).await;
        let _ = complete(&owned, &key_owned, &waiter, decision).await;
    });
    Ok(InvokeResult::Pending {
        message: "命令调用待审批".to_string(),
        approval_event_id: event_id,
    })
}

fn validate_params(
    def: &CommandDef,
    raw: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, String>> {
    for name in raw.keys() {
        if !def.parameters.contains_key(name) {
            return Err(VeilError::BadRequest {
                message: format!("未声明的参数 {name}"),
            });
        }
    }
    let mut out = BTreeMap::new();
    for (name, parameter) in &def.parameters {
        let Some(value) = raw.get(name) else {
            continue;
        };
        let rendered = match &parameter.kind {
            ParameterKind::Enum(values) => {
                let text = value.as_str().ok_or_else(|| VeilError::BadRequest {
                    message: format!("参数 {name} 须为字符串"),
                })?;
                if !values.iter().any(|allowed| allowed == text) {
                    return Err(VeilError::BadRequest {
                        message: format!("参数 {name} 取值 {text:?} 不在合法值域 {values:?} 内"),
                    });
                }
                text.to_string()
            }
            ParameterKind::Integer => match value {
                Value::Number(number) => {
                    number
                        .as_u64()
                        .map(|n| n.to_string())
                        .ok_or_else(|| VeilError::BadRequest {
                            message: format!("参数 {name} 须为非负整数"),
                        })?
                }
                Value::String(text) => {
                    if text.starts_with('-') {
                        return Err(VeilError::BadRequest {
                            message: format!("参数 {name} 不得以 `-` 开头（防选项注入）"),
                        });
                    }
                    text.parse::<u64>().map(|n| n.to_string()).map_err(|_| {
                        VeilError::BadRequest {
                            message: format!("参数 {name} 须为非负整数"),
                        }
                    })?
                }
                _ => {
                    return Err(VeilError::BadRequest {
                        message: format!("参数 {name} 须为整数"),
                    });
                }
            },
            ParameterKind::String => {
                let text = value.as_str().ok_or_else(|| VeilError::BadRequest {
                    message: format!("参数 {name} 须为字符串"),
                })?;
                if text.chars().count() > PARAM_STRING_MAX_CHARS {
                    return Err(VeilError::BadRequest {
                        message: format!("参数 {name} 超过 {PARAM_STRING_MAX_CHARS} 字符上限"),
                    });
                }
                if text.starts_with('-') {
                    return Err(VeilError::BadRequest {
                        message: format!("参数 {name} 不得以 `-` 开头（防选项注入）"),
                    });
                }
                text.to_string()
            }
        };
        out.insert(name.clone(), rendered);
    }
    for arg in &def.args {
        for name in placeholders(arg) {
            if !out.contains_key(name) {
                return Err(VeilError::BadRequest {
                    message: format!("缺少参数 {name}"),
                });
            }
        }
    }
    Ok(out)
}

async fn drive_pending(
    state: &(impl crate::service::credential::AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    pending: &Arc<PendingInvocation>,
) -> Option<Terminal> {
    if let Some(ExecutionEntry::Done(terminal)) = state.command().entry(key) {
        return Some((*terminal).clone());
    }
    match state.approval().decision(&pending.event_id).await {
        // 已落定（批准/拒绝）。
        Some(Some(decision)) => return Some(complete(state, key, pending, Some(decision)).await),
        // 票仍在待审：重入必须继续返回 202，不得当作超时。
        Some(None) => return None,
        // 票已消失：可能是并发 complete 正在执行（持 key 锁）或审批票被回收。
        None => {}
    }
    let lock = state.command().key_lock(key).await;
    let _guard = lock.lock().await;
    match state.command().entry(key) {
        Some(ExecutionEntry::Done(terminal)) => Some((*terminal).clone()),
        _ => {
            drop(_guard);
            Some(complete(state, key, pending, None).await)
        }
    }
}

async fn complete(
    state: &(impl crate::service::credential::AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    pending: &PendingInvocation,
    decision: Option<bool>,
) -> Terminal {
    let lock = state.command().key_lock(key).await;
    let _guard = lock.lock().await;
    if let Some(ExecutionEntry::Done(terminal)) = state.command().entry(key) {
        return (*terminal).clone();
    }
    // 审批已落定：后续执行期也必须保留在途槽位，否则轮询会误判超时并新建审批。
    state.command().hold_pending(
        key,
        &pending.event_id,
        execution_record_ttl(pending.timeout_secs),
    );
    let always = state
        .approval()
        .applied_always(&pending.event_id)
        .await
        .unwrap_or(false);
    clear_terminal_pending(state, &pending.pending_key, &pending.event_id).await;
    let terminal = match decision {
        Some(true) => {
            if always {
                state
                    .command()
                    .grants
                    .insert(&pending.caller_path, &pending.command_id, &pending.host)
                    .await;
            }
            let output = run_command(
                state,
                &pending.host,
                &pending.program,
                &pending.argv,
                pending.timeout_secs,
            )
            .await;
            terminal_from_output(
                Some(pending.event_id.clone()),
                "approved",
                &pending.host,
                output,
            )
        }
        Some(false) => Terminal::Denied {
            approval_status: "denied".to_string(),
            approval_event_id: Some(pending.event_id.clone()),
            message: "命令审批被拒绝".to_string(),
        },
        None => Terminal::ApprovalTimeout {
            approval_event_id: pending.event_id.clone(),
            message: "命令审批超时，按拒绝处理".to_string(),
        },
    };
    log_terminal(
        state,
        &CallerContext {
            caller_path: pending.caller_path.clone(),
            caller_hash: pending.caller_hash.clone(),
            registered: true,
            known_entry: true,
        },
        &pending.downstream,
        &pending.command_id,
        &pending.host,
        &pending.params_json,
        &terminal,
    )
    .await;
    state.command().set_done(key, terminal.clone());
    state.command().remove_lock(key).await;
    terminal
}

async fn run_command(
    state: &impl crate::service::credential::AppStateParts,
    host: &str,
    program: &std::path::Path,
    argv: &[String],
    timeout_secs: u64,
) -> std::result::Result<CommandOutput, String> {
    let backend = state.command().backend.clone();
    let host = host.to_string();
    let program = program.to_path_buf();
    let argv = argv.to_vec();
    let timeout = Duration::from_secs(timeout_secs.max(1));
    tokio::task::spawn_blocking(move || backend.run_blocking(&host, &program, &argv, timeout))
        .await
        .map_err(|err| format!("执行任务异常: {err}"))?
        .map_err(|err| format!("命令启动失败: {err:#}"))
}

fn terminal_from_output(
    event_id: Option<String>,
    approval_status: &str,
    host: &str,
    output: std::result::Result<CommandOutput, String>,
) -> Terminal {
    match output {
        Ok(output) => Terminal::Executed {
            approval_status: approval_status.to_string(),
            approval_event_id: event_id,
            host: host.to_string(),
            output,
        },
        Err(message) => Terminal::ExecError {
            approval_status: approval_status.to_string(),
            approval_event_id: event_id,
            message,
        },
    }
}

async fn log_terminal(
    state: &impl crate::service::credential::AppStateParts,
    caller: &CallerContext,
    downstream: &str,
    command_id: &str,
    host: &str,
    params_json: &str,
    terminal: &Terminal,
) {
    let log = crate::service::command::InvocationLog {
        id: invocation_id(),
        ts_secs: now_secs(),
        caller_path: caller.caller_path.clone(),
        caller_hash: caller.caller_hash.clone(),
        downstream: downstream.to_string(),
        command: command_id.to_string(),
        host: host.to_string(),
        params_json: params_json.to_string(),
        approval_status: terminal.approval_status().to_string(),
        exec_status: terminal.exec_status().to_string(),
        approval_event_id: match terminal {
            Terminal::Executed {
                approval_event_id, ..
            }
            | Terminal::Denied {
                approval_event_id, ..
            }
            | Terminal::ExecError {
                approval_event_id, ..
            } => approval_event_id.clone(),
            Terminal::ApprovalTimeout {
                approval_event_id, ..
            } => Some(approval_event_id.clone()),
        },
        exit_code: terminal.exit_code(),
        stdout: terminal
            .output()
            .map(|output| output.stdout.clone())
            .unwrap_or_default(),
        stderr: terminal
            .output()
            .map(|output| output.stderr.clone())
            .unwrap_or_default(),
        duration_ms: terminal
            .output()
            .map(|output| output.duration_ms)
            .unwrap_or(0),
    };
    if let Err(err) = state.command().log.insert(log).await {
        tracing::warn!("命令调用日志写入失败: {err:#}");
    }
    let summary = format!(
        "{command_id}@{host} by {} -> {}",
        caller.caller_path,
        terminal.exec_status()
    );
    state.admin_state().push_event("command", &summary, None);
}

fn execution_key(
    caller_path: &str,
    caller_hash: &str,
    command_id: &str,
    host: &str,
    params_json: &str,
) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    for part in [caller_path, caller_hash, command_id, host, params_json] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn invocation_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    format!("inv-{}-{}", now_secs(), SEQ.fetch_add(1, Ordering::Relaxed))
}
