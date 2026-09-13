//! 服务层索引：仅模块声明与旧路径重导出（A1 解耦后本文件零业务逻辑）。
//!
//! 依赖方向：`state` 聚合本层类型（`state -> service`）；本层业务经
//! [`credential::AppStateParts`] trait 读态，不再命名 `crate::state`
//! （`service -> state` 边已断，单向无环）。

pub mod admin;
pub mod audit;
pub mod audit_hold;
pub mod block_inject;
pub mod credential;
/// §3 脱敏子模块（单向依赖：只读 `state` 经调用方注入，不触网络与路由）。
pub mod credential_vault;
pub mod json_walk;
pub mod llm_gateway;
pub mod matrix;
pub mod metrics;
pub mod pii;
pub mod redaction;
pub mod sse;
pub mod tpm;

/// 旧路径兼容：`crate::service::{handle_credential, RateTable, ...}`
/// 一律经本重导出解析，调用方零改。
pub use credential::*;

#[cfg(test)]
mod declaration_lock {
    // A1/D1 声明锁定：本文件头部声明（service 零 `crate::state` 命名 +
    // 零 axum 依赖，唯一例外为纯数据 `HeaderMap` 白名单）由本测试自动化证实。
    // 模式串运行期拼接，避免测试自身命中扫描。

    #[test]
    fn service_layer_declaration_matches_implementation() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        assert!(!files.is_empty(), "扫描根须存在");
        let banned = [
            format!("use crate::{}", "state"),
            format!("crate::{}::AppState", "state"),
            format!("State<{}>", "AppState"),
        ];
        let axum_use = ["use", "axum"].join(" ");
        let axum_allow = ["llm_gateway/hop.rs", "llm_gateway/mod.rs"];
        for path in files {
            let rel = path
                .strip_prefix(&root)
                .expect("子路径")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&path).expect("读取成功");
            for pat in &banned {
                assert!(
                    !src.contains(pat.as_str()),
                    "src/service/{rel} 命中禁用模式 {pat:?}（A1 层声明失真）"
                );
            }
            if src.contains(&axum_use) {
                assert!(
                    axum_allow.contains(&rel.as_str()),
                    "src/service/{rel} 出现 {axum_use}，非纯数据白名单（A1/X6）"
                );
            }
        }
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("目录可读").flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_rs(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }

    /// H1/D1 兼容垫片零生产引用守护：垫片路径字面仅允许出现在垫片文件本体
    /// （注释/重导出）与测试文件；任何生产新增引用即失败。模式串运行期拼接，
    /// 避免测试自身命中扫描（与上方声明锁定同模式）。
    #[test]
    fn audit_hold_zero_production_refs() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        assert!(!files.is_empty(), "扫描根须存在");
        let needle = format!("audit_{}::", "hold");
        let shim = "service/audit_hold.rs";
        let mut offenders = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&root)
                .expect("子路径")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&path).expect("读取成功");
            if src.contains(&needle) && rel != shim && !rel.contains("test") {
                offenders.push(rel);
            }
        }
        assert!(
            offenders.is_empty(),
            "垫片零生产引用守护失败（仅垫片与测试白名单允许）：{offenders:?}"
        );
    }

    /// H7/D7 锁序不变量检查（纯函数，供守护测试与逆序样例复用）：返回违规描述，
    /// 空表示合规。登记写路径：vault_ops 写点、`account_rule`、keepalive gate。
    fn lock_order_violations(rel: &str, src: &str) -> Vec<String> {
        let mut out = Vec::new();
        match rel {
            "service/credential/vault_ops.rs" => {
                let mut pending: Option<usize> = None;
                for (i, line) in src.lines().enumerate() {
                    if line.contains("registry_save_lock().lock()") {
                        pending = Some(i);
                    } else if line.contains("registry().write().await") {
                        pending = match pending.take() {
                            Some(save) if save < i => None,
                            _ => {
                                out.push(format!(
                                    "{rel}:{} `registry().write()` 先于 `registry_save_lock`（锁序违例）",
                                    i + 1
                                ));
                                None
                            }
                        };
                    }
                }
                // 未登记写路径守护：写点数量须与登记数一致（新增写路径需登记）。
                const REGISTERED_WRITE_SITES: usize = 4;
                let n = src.matches("registry().write().await").count();
                if n != REGISTERED_WRITE_SITES {
                    out.push(format!(
                        "{rel}: 写路径计数 {n} != 登记 {REGISTERED_WRITE_SITES}（新增写路径须登记）"
                    ));
                }
            }
            "service/pii/custom.rs" => {
                let ordered = fn_body(src, "fn account_rule").is_some_and(|body| {
                    body.find("self.strikes.lock()")
                        .is_some_and(|s| body.find("self.disabled.lock()").is_some_and(|d| s < d))
                });
                if !ordered {
                    out.push(format!(
                        "{rel}: `account_rule` 中 `strikes` 未先于 `disabled`（锁序违例）"
                    ));
                }
            }
            "service/audit/hold.rs" => {
                let gapless = fn_body(src, "pub fn spawn_gated_with_interval")
                    .is_some_and(|body| !body.contains(".lock()"));
                if !gapless {
                    out.push(format!(
                        "{rel}: keepalive gate 逆向获取 hold 锁（锁序违例）"
                    ));
                }
            }
            _ => {}
        }
        out
    }

    /// 取 `sig` 起、行首 `}` 止的顶层函数体切片（登记函数的边界提取）。
    fn fn_body<'a>(src: &'a str, sig: &str) -> Option<&'a str> {
        let rest = &src[src.find(sig)?..];
        let end = rest.find("\n}")?;
        Some(&rest[..end])
    }

    #[test]
    fn lock_order_invariants() {
        let reversed = "let mut registry = state.registry().write().await;\n\
                        let save_guard = state.registry_save_lock().lock().await;";
        assert!(
            !lock_order_violations("service/credential/vault_ops.rs", reversed).is_empty(),
            "逆序样例须被拦截"
        );
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for rel in [
            "service/credential/vault_ops.rs",
            "service/pii/custom.rs",
            "service/audit/hold.rs",
        ] {
            let src = std::fs::read_to_string(root.join(rel)).expect("登记文件可读");
            let v = lock_order_violations(rel, &src);
            assert!(v.is_empty(), "锁序守护失败: {v:?}");
        }
    }

    /// H8/D8 同步 TPM 子进程入口标记（模式串运行期拼接，避免测试自身命中扫描）。
    fn tpm_sync_markers() -> [String; 4] {
        [
            format!("Real{}", "Tpm"),
            format!("tpm2{}", "_"),
            "startup_tpm_in".to_string(),
            "require_hardware_tpm".to_string(),
        ]
    }

    /// 剥离字符串字面量与行注释：避免字面量/注释中的括号与标记干扰结构化扫描。
    fn strip_literals(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut chars = src.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    out.push(' ');
                    let mut esc = false;
                    for d in chars.by_ref() {
                        out.push(if d == '\n' { '\n' } else { ' ' });
                        if esc {
                            esc = false;
                        } else if d == '\\' {
                            esc = true;
                        } else if d == '"' {
                            break;
                        }
                    }
                }
                '/' if chars.peek() == Some(&'/') => {
                    while let Some(&d) = chars.peek() {
                        if d == '\n' {
                            break;
                        }
                        chars.next();
                        out.push(' ');
                    }
                }
                _ => out.push(c),
            }
        }
        out
    }

    /// 结构化作用域擦除：把每个 `needle` 之后的首个 `{...}` 平衡块内容抹为空格
    /// （保留换行，行数/行列可继续定位）；`needle` 与 `{` 之间出现 `;` 视为无闭包体，
    /// 不擦除（避免越界擦除掩藏违规）。缺真实常量的括号解析不参与，故先 `strip_literals`。
    fn scrub_scopes(src: &str, needles: &[&str]) -> String {
        let chars: Vec<char> = src.chars().collect();
        let mut remove = vec![false; chars.len()];
        for needle in needles {
            let n: Vec<char> = needle.chars().collect();
            if n.is_empty() {
                continue;
            }
            let mut i = 0;
            while i + n.len() <= chars.len() {
                if chars[i..i + n.len()] == n[..] {
                    let mut open = None;
                    let mut scan = i + n.len();
                    while scan < chars.len() {
                        match chars[scan] {
                            '{' => {
                                open = Some(scan);
                                break;
                            }
                            ';' => break,
                            _ => {}
                        }
                        scan += 1;
                    }
                    if let Some(open) = open {
                        let mut depth = 0i32;
                        let mut close = None;
                        let mut scan = open;
                        while scan < chars.len() {
                            match chars[scan] {
                                '{' => depth += 1,
                                '}' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        close = Some(scan);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                            scan += 1;
                        }
                        if let Some(close) = close {
                            for slot in remove.iter_mut().take(close + 1).skip(i) {
                                *slot = true;
                            }
                            i = close + 1;
                            continue;
                        }
                    }
                }
                i += 1;
            }
        }
        chars
            .iter()
            .enumerate()
            .map(|(idx, &c)| if remove[idx] && c != '\n' { ' ' } else { c })
            .collect()
    }

    /// H8/D8 结构化 TPM 同步子进程守护（纯函数）：返回违规描述（空 = 合规）。
    ///
    /// 受约束作用域（相对旧「整文件白名单 + `RealTpm`/`tpm2_` 标记探测」收窄）：
    /// - `service/tpm.rs`：同步原语本体，本身即受约束边界；
    /// - `main.rs`：`#[tokio::main]` 启动链模块（启动期先于 serve，同步 TPM 按设计）；
    /// - 其余文件（含原被整文件放行的 `keepass.rs`）：仅 `spawn_blocking` 闭包内， 外加
    ///   `keepass.rs::tpm_password_provider`（惰性 provider 工厂，仅被阻塞闭包调用）。
    fn tpm_sync_subprocess_violations(rel: &str, src: &str) -> Vec<String> {
        if matches!(rel, "service/tpm.rs" | "main.rs") {
            return Vec::new();
        }
        let stripped = strip_literals(src);
        let mut needles: Vec<&str> = vec!["spawn_blocking"];
        if rel == "keepass.rs" {
            needles.push("pub fn tpm_password_provider");
        }
        let scoped = scrub_scopes(&stripped, &needles);
        let markers = tpm_sync_markers();
        let mut out = Vec::new();
        for (i, line) in scoped.lines().enumerate() {
            for m in &markers {
                if line.contains(m.as_str()) {
                    out.push(format!(
                        "{rel}:{} 同步 TPM 标记 `{m}` 越出受约束作用域（须在 spawn_blocking 内）",
                        i + 1
                    ));
                }
            }
        }
        out
    }

    #[test]
    fn tpm_sync_subprocess_guard() {
        // 受约束路径通过：`spawn_blocking` 闭包内的同步 TPM 调用不判违规。
        let scoped = "fn a() { tokio::task::spawn_blocking(move || { \
                      let _ = RealTpm::new().is_available(); }); }";
        assert!(
            tpm_sync_subprocess_violations("handler/foo.rs", scoped).is_empty(),
            "受约束闭包路径须放行"
        );
        // 越界路径失败：async 直调同步 TPM 门禁入口即违规。
        let unscoped = "async fn b() { let _ = startup_tpm_in(\"/data/tpm\", false); }";
        assert!(
            !tpm_sync_subprocess_violations("handler/foo.rs", unscoped).is_empty(),
            "越界直调须被拦截"
        );
        // 真实源码树：受约束作用域外零同步 TPM 调用点。
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        let offenders: Vec<String> = files
            .into_iter()
            .flat_map(|path| {
                let rel = path
                    .strip_prefix(&root)
                    .expect("子路径")
                    .to_string_lossy()
                    .replace('\\', "/");
                let src = std::fs::read_to_string(&path).expect("读取成功");
                tpm_sync_subprocess_violations(&rel, &src)
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "TPM 同步子进程调用越出受约束作用域: {offenders:?}"
        );
    }

    #[test]
    fn tpm_sync_guard_bypass_rejected() {
        // 别名导入绕过：旧守护仅探 `RealTpm`/`tpm2_` 字面，`use ... as helper` 后调用
        // 无标记即漏放行；结构化守护按入口名捕获，别名导入行本身即命中。
        let alias = "use crate::service::tpm::startup_tpm_in as helper;\n\
                     async fn h() { let _ = helper(\"/data/tpm\", false); }";
        assert!(
            !tpm_sync_subprocess_violations("handler/foo.rs", alias).is_empty(),
            "别名导入须被拦截"
        );
        // 非受约束路径：无 `RealTpm`/`tpm2_` 字面、经门禁函数入口直调，旧守护漏网、结构化守护须拦。
        let gate = "async fn h() { let _ = require_hardware_tpm(tpm); }";
        assert!(
            !tpm_sync_subprocess_violations("handler/foo.rs", gate).is_empty(),
            "门禁入口直调须被拦截"
        );
    }
}
