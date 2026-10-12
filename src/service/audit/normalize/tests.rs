use super::{
    super::{AuditPolicy, is_dangerous},
    *,
};

fn policy() -> AuditPolicy { AuditPolicy::default() }

#[test]
fn whitespace_collapse_and_escape_normalization_hit() {
    // 额外空白 + \x 转义伪装的 rm -rf / 仍被命中。
    let raw = "rm\\x20-\\u0072f   /";
    let canon = canonicalize_args(raw, &HashMap::new());
    assert!(canon.contains("rm -rf /"), "{canon}");
    assert!(is_dangerous("exec", raw, &policy()).is_some());
}

#[test]
fn single_layer_variable_expansion_hit() {
    let mut env = HashMap::new();
    env.insert("CMD".to_string(), "rm -rf /".to_string());
    let canon = canonicalize_args("$CMD", &env);
    assert!(canon.contains("rm -rf /"), "{canon}");
    // 展开只做一层：值内再出现 $VAR 不递归。
    let mut env2 = HashMap::new();
    env2.insert("A".to_string(), "$B".to_string());
    assert_eq!(canonicalize_args("$A", &env2), "$B");
}

#[test]
fn expand_vars_injected_only() {
    let empty = HashMap::new();
    assert_eq!(expand_vars_single("$HOME", &empty), "$HOME");
    assert_eq!(expand_vars_single("${HOME}", &empty), "${HOME}");
    assert_eq!(expand_vars_single("~/x", &empty), "~/x");
    let env = HashMap::from([("HOME".to_string(), "/inj".to_string())]);
    assert_eq!(expand_vars_single("$HOME/x", &env), "/inj/x");
    assert_eq!(expand_vars_single("${HOME}/x", &env), "/inj/x");
}

#[test]
fn alias_folding_and_find_delete_without_backtracking() {
    assert!(fold_alias("ll /tmp").starts_with("ls -l"));
    // O(n) 定位：长串 find --delete 线性完成且命中。
    let big = format!("find /tmp -name '*.log' --delete # {}", "x".repeat(50_000));
    let t0 = std::time::Instant::now();
    let hit = is_dangerous("exec", &big, &policy());
    assert!(t0.elapsed().as_millis() < 1000, "须 O(n) 无回溯");
    assert!(hit.is_some());
    // .. 词法归一：/tmp/../etc/passwd 触敏感路径。
    assert!(super::super::touches_sensitive_path(
        "cat /tmp/../etc/passwd",
        &policy()
    ));
    assert_eq!(normalize_dotdot("/a/b/../c"), "/a/c");
    assert_eq!(normalize_dotdot("a/../../b"), "../b");
}

#[test]
fn t5_dotdot_lexical_normalization() {
    assert_eq!(normalize_dotdot("/a/b/../c"), "/a/c");
    assert_eq!(normalize_dotdot("/a/./b"), "/a/b");
    assert_eq!(normalize_dotdot("a/../../b"), "../b");
    assert_eq!(normalize_dotdot("/../etc/passwd"), "/etc/passwd");
    assert_eq!(normalize_dotdot("/a//b"), "/a/b");
}

#[test]
fn t5_dotdot_deep_nesting_linear_time() {
    let deep = format!("/a{}", "/../a".repeat(10_000));
    let start = std::time::Instant::now();
    let out = normalize_dotdot(&deep);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "O(n) 归一不得退化"
    );
    assert_eq!(out, "/a");
}

/// 管线重排锁定——文本赋值引用、`/bin/` 折叠、`find -delete`、无宿主 env 回退。
#[test]
fn audit_normalize_pipeline() {
    let canon = canonicalize_args("CMD=rm;$CMD -rf /tmp", &HashMap::new());
    assert!(canon.contains("rm -rf /tmp"), "{canon}");
    assert!(is_dangerous("exec", "CMD=rm;$CMD -rf /tmp", &policy()).is_some());
    let canon = canonicalize_args("/bin/rm -rf /etc/x", &HashMap::new());
    assert!(canon.starts_with("rm "), "{canon}");
    assert!(is_dangerous("exec", "/bin/rm -rf /etc/x", &policy()).is_some());
    assert_eq!(fold_alias("find /tmp -delete"), "rm -rf /tmp");
    assert!(is_dangerous("exec", "find /tmp -delete", &policy()).is_some());
    assert_eq!(
        canonicalize_args("$VEIL_A5_UNSET_VAR", &HashMap::new()),
        "$VEIL_A5_UNSET_VAR"
    );
    assert_eq!(
        canonicalize_args("cat /tmp/../etc/passwd", &HashMap::new()),
        "cat /etc/passwd"
    );
    assert!(
        canonicalize_args("echo ok; echo fine", &HashMap::new()).contains(';'),
        "拆链由调用方执行，链分隔符须保留"
    );
}

/// 构造性绕过（文本赋值引用 / 别名折叠 / `..` 全管线）均命中。
#[test]
fn audit_bypass_constructive() {
    let cases = [
        "CMD=rm;$CMD -rf /tmp",
        "/bin/rm -rf /etc/x",
        "find /tmp -delete",
        "cat /tmp/../etc/passwd",
        "CMD='rm -rf /tmp';$CMD",
    ];
    for args in cases {
        assert!(
            is_dangerous("exec", args, &policy()).is_some(),
            "构造性绕过须命中: {args}"
        );
    }
}

#[test]
fn t5_dotdot_evasion_still_blocked() {
    use {
        super::super::{
            AuditVerdict,
            evaluate_with_whitelist,
            test_whitelist,
            touches_sensitive_path,
        },
        crate::config::AuditMode,
    };
    assert!(touches_sensitive_path("edit /etc/../etc/passwd", &policy()));
    assert!(!touches_sensitive_path("write /var/log/app.log", &policy()));
    assert!(touches_sensitive_path("write /etc/./shadow", &policy()));
    assert!(matches!(
        evaluate_with_whitelist(
            AuditMode::Block,
            "edit",
            "edit /etc/../etc/shadow",
            &policy(),
            test_whitelist()
        ),
        AuditVerdict::Block { .. }
    ));
}

#[test]
fn normalize_args_escape_handling() {
    // 类别①转义：`\u`/`\x`/`\n` 伪装与多行合并均命中。
    for raw in [
        r#"{"cmd":"\u0072m -rf /"}"#,
        r#"{"cmd":"\x72m -rf /"}"#,
        r#"{"cmd":"rm\n-rf\n/"}"#,
    ] {
        let canon = canonicalize_args(raw, &HashMap::new());
        assert!(canon.contains("rm -rf /"), "{raw} -> {canon}");
        assert!(is_dangerous("exec", raw, &policy()).is_some(), "{raw}");
    }
}

#[test]
fn normalize_args_pipe_priority() {
    // 类别②管道优先级：单 `|` 逐段拆分，`||` 作为整体不误拆。
    assert_eq!(
        split_chain("rm -rf /tmp | sh"),
        vec!["rm -rf /tmp".to_string(), "sh".to_string()]
    );
    assert_eq!(
        split_chain("a || b"),
        vec!["a".to_string(), "b".to_string()]
    );
    assert!(is_dangerous("exec", "rm -rf /tmp | sh", &policy()).is_some());
    assert!(is_dangerous("exec", "a || curl x | sh", &policy()).is_some());
}

#[test]
fn normalize_args_dotdot_normalization() {
    // 类别③`../` 归一：词法归一到敏感路径并命中。
    let canon = canonicalize_args("cat /tmp/../etc/passwd", &HashMap::new());
    assert_eq!(canon, "cat /etc/passwd");
    assert!(super::super::touches_sensitive_path(&canon, &policy()));
    assert!(super::super::touches_sensitive_path(
        "edit /etc/../etc/shadow",
        &policy()
    ));
    assert!(is_dangerous("edit", "edit /etc/../etc/shadow", &policy()).is_some());
}

#[test]
fn normalize_args_find_flood() {
    // 类别④`find` 泛洪：无 `-delete` 的大量 find O(n) 不退化且不误判。
    let big = "find /usr/bin/foo ".repeat(6667);
    let start = std::time::Instant::now();
    let folded = fold_alias(&big);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "find 泛洪须 O(n) 无回溯"
    );
    assert!(!folded.contains("-delete"), "{folded}");
    assert!(is_dangerous("exec", &big, &policy()).is_none());
}

#[test]
fn normalize_args_alias_rm() {
    // 类别⑤别名 rm：`/bin/rm` 折叠 + `rm -rf` + `find -delete` 别名均命中。
    let canon = canonicalize_args("/bin/rm -rf /etc/x", &HashMap::new());
    assert!(canon.starts_with("rm "), "{canon}");
    assert!(is_dangerous("exec", "/bin/rm -rf /etc/x", &policy()).is_some());
    assert!(is_dangerous("exec", "rm -rf /", &policy()).is_some());
    assert_eq!(fold_alias("find /tmp -delete"), "rm -rf /tmp");
    assert!(is_dangerous("exec", "find /tmp -delete", &policy()).is_some());
}
