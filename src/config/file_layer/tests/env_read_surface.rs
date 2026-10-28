//! 进程 env 读取面机检（tasks 3.4；spec `docs-contract-sync` / `config-env-surface`）：
//! 扫描 `src/**` 生产代码中 `std::env::var`/`var_os`/`vars`/`vars_os` 调用点，断言其
//! 集合恰为白名单 ∪ {`from_env` 唯一收集点、审计快照}。新增未登记的生产调用点即测试红；
//! 测试专用代码（`*/tests.rs`、`*/tests/**`、内联 `#[cfg(test)]` 模块）不参与扫描。

use {
    crate::config::env_surface::CONFIG_ENV_WHITELIST,
    std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    },
};

/// `std::env::` 下的四个读取函数种类。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ReadKind {
    Var,
    VarOs,
    Vars,
    VarsOs,
}

/// 一处读取调用点：相对 crate 根的文件路径（如 `src/logging.rs`）+ 种类 + 被读名字
/// （`var`/`var_os` 的字面量或常量标识符；`vars`/`vars_os` 为 `None`）。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CallSite {
    file: String,
    kind: ReadKind,
    name: Option<String>,
}

fn site(file: &str, kind: ReadKind, name: Option<&str>) -> CallSite {
    CallSite {
        file: file.to_string(),
        kind,
        name: name.map(str::to_string),
    }
}

/// 期望的生产读取面：白名单名 + 两处已登记例外。
///
/// - `env_parse/mod.rs`：`Config::from_env` 的**唯一**全量收集点，收集后立即交白名单过滤；
/// - `logging.rs`：`RUST_LOG` 日志层直读（早于配置加载，分层所限）；
/// - `service/tpm.rs`：`VEIL_ALLOW_MOCK_TPM` TPM 层直读；
/// - `service/audit/policy.rs`：**审计快照例外**——`capture_process_env` 于策略加载时 快照 `HOME`
///   单列 + 全量 vars，仅供命令文本展开与 `~/` 展开，**仅文本展开、不回写 配置**（工程参考 §1
///   例外①）。
fn expected_sites() -> BTreeSet<CallSite> {
    [
        site("src/config/env_parse/mod.rs", ReadKind::Vars, None),
        site("src/logging.rs", ReadKind::Var, Some("RUST_LOG")),
        site(
            "src/service/tpm.rs",
            ReadKind::Var,
            Some("VEIL_ALLOW_MOCK_TPM"),
        ),
        site("src/service/audit/policy.rs", ReadKind::Var, Some("HOME")),
        site("src/service/audit/policy.rs", ReadKind::Vars, None),
    ]
    .into_iter()
    .collect()
}

/// 递归收集生产 `.rs` 文件：跳过 `tests.rs` 与名为 `tests` 的目录（测试专用代码）。
fn collect_production_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).unwrap_or_else(|err| panic!("读取目录 {root:?} 失败: {err}"));
    for entry in entries {
        let path = entry.expect("读取目录项").path();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if file_name != "tests" {
                collect_production_rs(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") && file_name != "tests.rs"
        {
            out.push(path);
        }
    }
}

/// 去掉内联 `#[cfg(test)]` 项（本项目测试外置于 `tests.rs`，此处为防内联回归的兜底）。
/// 按行花括号配平：`#[cfg(test)]` 后首个项若为 `mod X { ... }` 整块丢弃，若为 `mod X;`
/// 或单行项则仅丢弃该项。字符串内不配平的极少数场景不影响本用途。
fn strip_inline_cfg_test(src: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    let mut depth: i32 = 0;
    for line in src.lines() {
        if skipping {
            depth += brace_delta(line);
            if depth <= 0 {
                skipping = false;
                depth = 0;
            }
            continue;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with("#[cfg(test)]") {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let rest = trimmed.trim_start_matches("#[cfg(test)]").trim();
        if rest.is_empty() {
            skipping = true;
        } else if !rest.ends_with(';') {
            depth = brace_delta(rest);
            skipping = depth > 0;
        }
    }
    out
}

/// 一行中的 `{`/`}` 净增减。
fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |acc, c| match c {
        '{' => acc + 1,
        '}' => acc - 1,
        _ => acc,
    })
}

/// 在源码文本中找出所有 `std::env::{var,var_os,vars,vars_os}` 调用点。
/// 仅匹配全限定 `std::env::` 形式；经 `use std::env::var` 导入的简写调用不在本扫描面。
fn find_env_reads(src: &str) -> Vec<(ReadKind, Option<String>)> {
    const PREFIX: &str = "std::env::";
    let mut found = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find(PREFIX) {
        let after = &rest[pos + PREFIX.len()..];
        let ident: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let tail = &after[ident.len()..];
        let kind = match ident.as_str() {
            "var" => Some(ReadKind::Var),
            "var_os" => Some(ReadKind::VarOs),
            "vars" => Some(ReadKind::Vars),
            "vars_os" => Some(ReadKind::VarsOs),
            _ => None,
        };
        if let Some(kind) = kind
            && tail.starts_with('(')
        {
            found.push((kind, extract_arg(tail)));
        }
        rest = tail;
    }
    found
}

/// 取调用实参的首个名字：`"LITERAL"` 内容或裸标识符；`vars`/`vars_os` 无参返回 `None`。
fn extract_arg(call: &str) -> Option<String> {
    let inner = call.trim_start_matches('(').trim_start();
    if let Some(rest) = inner.strip_prefix('"') {
        let end = rest.find('"').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    let ident: String = inner
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

/// 扫描给定根目录下的生产代码，返回全部读取调用点。
fn scan_env_reads(root: &Path) -> BTreeSet<CallSite> {
    let mut files = Vec::new();
    collect_production_rs(root, &mut files);
    files.sort();
    let mut sites = BTreeSet::new();
    for path in files {
        let src =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("读取 {path:?} 失败: {err}"));
        let production = strip_inline_cfg_test(&src);
        let rel = path
            .strip_prefix(root)
            .expect("路径须在根内")
            .to_string_lossy()
            .replace('\\', "/");
        for (kind, name) in find_env_reads(&production) {
            sites.insert(CallSite {
                file: format!("src/{rel}"),
                kind,
                name,
            });
        }
    }
    sites
}

#[test]
fn production_env_read_surface_is_registered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let observed = scan_env_reads(&root);
    let expected = expected_sites();
    assert_eq!(
        observed,
        expected,
        "生产 `std::env::var*` 调用点须恰为白名单 ∪ 已登记例外；\
         新增读取须在本测试登记并同步工程参考 §1（多={:?}，少={:?}）",
        observed.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&observed).collect::<Vec<_>>()
    );

    let whitelist: BTreeSet<&str> = CONFIG_ENV_WHITELIST.iter().copied().collect();
    for call in &observed {
        if let Some(name) = &call.name {
            assert!(
                whitelist.contains(name.as_str()),
                "具名读取 {name}（{}）不在白名单内：进程 env 读取面只允许白名单名",
                call.file
            );
        }
    }
}

#[test]
fn scanner_detects_new_production_call_site() {
    let dir = std::env::temp_dir().join(format!("veil-read-surface-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("建临时目录");
    let file = dir.join("new_prod.rs");
    fs::write(&file, "fn f() { let _ = std::env::var(\"BRAND_NEW\"); }\n").expect("写临时文件");
    let found = scan_env_reads(&dir);
    assert!(
        found.contains(&site("src/new_prod.rs", ReadKind::Var, Some("BRAND_NEW"))),
        "新增未登记调用点须被捕获: {found:?}"
    );
    fs::remove_file(&file).ok();
    fs::remove_dir_all(&dir).ok();
}
