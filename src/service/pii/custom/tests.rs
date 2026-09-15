use {
    crate::service::pii::detector::{
        RE_DOS_BUDGET_MS,
        test_support::{detector, empty_cred},
    },
    std::time::Duration,
};

#[tokio::test]
async fn b4_cjk_mixed_and_reserved_edges() {
    use super::super::detector::is_reserved_ip;
    assert!(is_reserved_ip("10.1.2.3", "ipv4"));
    assert!(!is_reserved_ip("8.8.8.8", "ipv4"));
    assert!(is_reserved_ip("fc00::1", "ipv6"));
    assert!(!is_reserved_ip("2001:4860:4860::8888", "ipv6"));
    let d = detector();
    d.load_custom_patterns(&[(
        "emp_no".to_string(),
        r"(?P<emp_no>(?<![\d])工号\d{6}(?![\d]))".to_string(),
    )]);
    let hits = d
        .scan_custom("Hi联系工号123456处理Done 上线", &empty_cred())
        .await;
    assert!(hits.iter().any(|h| h.1 == "工号123456"), "{hits:?}");
    d.load_dict(&[("张三".to_string(), "name".to_string())]);
    let hits = d.scan_dict_sync("Hi 张三，Done 来了", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    // ASCII 字母数字紧贴粘连按边界口径阻断（防误伤，不断字即正确）。
    let hits = d.scan_dict_sync("Hi张三Done 来了", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    let hits = d.scan_dict_sync("中文测试文本", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "中文测试文本"), "{hits:?}");
}

#[test]
fn custom_regex_with_word_boundary_rejected() {
    let d = detector();
    let n = d.load_custom_patterns(&[("bad".to_string(), r"\bfoo\d+\b".to_string())]);
    assert_eq!(n, 0);
    assert!(d.custom_names_snapshot().is_empty());
    // 与内置重名同样拒绝。
    let n = d.load_custom_patterns(&[("phone".to_string(), r"1\d{10}".to_string())]);
    assert_eq!(n, 0);
    // 合法 lookaround 规则加载成功。
    let n = d.load_custom_patterns(&[(
        "emp_no".to_string(),
        r"(?P<emp_no>(?<![\d])工号\d{6}(?![\d]))".to_string(),
    )]);
    assert_eq!(n, 1);
}

#[tokio::test]
async fn malicious_pattern_fast_reject_and_disable_after_three_timeouts() {
    // 引擎层：`^(a+)+$` 对抗性输入微秒级返回，远快于 100ms 预算（不挂起主链）。
    let d = detector();
    d.load_custom_patterns(&[("evil".to_string(), r"^(a+)+$".to_string())]);
    assert!(d.custom_names_snapshot().contains(&"evil".to_string()));
    assert_eq!(RE_DOS_BUDGET_MS, 100);
    let input = "a".repeat(2000) + "b";
    let start = std::time::Instant::now();
    let hits = d.scan_custom(&input, &empty_cred()).await;
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "恶意模式必须远快于预算返回"
    );
    assert!(hits.iter().all(|h| h.0 != "evil"));
    // 状态机层：连续 3 次超时停用（确定性单测记账逻辑）。
    let d2 = detector();
    d2.load_custom_patterns(&[("slow".to_string(), r"slow\d+".to_string())]);
    assert!(!d2.disabled_snapshot().contains(&"slow".to_string()));
    d2.account_rule("slow", true);
    d2.account_rule("slow", true);
    assert!(!d2.disabled_snapshot().contains(&"slow".to_string()));
    d2.account_rule("slow", true);
    assert!(d2.disabled_snapshot().contains(&"slow".to_string()));
    // 成功清零：超时 2 次后成功则计数重置。
    let d3 = detector();
    d3.load_custom_patterns(&[("flaky".to_string(), r"flaky\d+".to_string())]);
    d3.account_rule("flaky", true);
    d3.account_rule("flaky", true);
    d3.account_rule("flaky", false);
    d3.account_rule("flaky", true);
    d3.account_rule("flaky", true);
    assert!(!d3.disabled_snapshot().contains(&"flaky".to_string()));
}

#[tokio::test]
async fn redos_wall_clock_absolute_ceiling_beyond_budget_assertion() {
    // T3/7.2：对抗输入在明确绝对上界常量内返回，不依赖 `RE_DOS_BUDGET_MS`
    // 预算断言，也不依赖连续三次禁用的记账路径（独立兜底锁）。
    let d = detector();
    d.load_custom_patterns(&[("evil-abs".to_string(), r"^(a+)+$".to_string())]);
    let input = format!("{}b", "a".repeat(2000));
    let start = std::time::Instant::now();
    let hits = d.scan_custom(&input, &empty_cred()).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(super::REDOS_WALL_CLOCK_CEILING_MS),
        "对抗扫描须在绝对上界 {}ms 内返回，实际 {elapsed:?}",
        super::REDOS_WALL_CLOCK_CEILING_MS
    );
    assert!(hits.iter().all(|h| h.0 != "evil-abs"), "{hits:?}");
    assert!(
        !d.disabled_snapshot().contains(&"evil-abs".to_string()),
        "单次超时不得触发三连禁用记账（上界与记账解耦）"
    );
}

#[test]
fn dict_standalone_scan_with_cjk_boundary() {
    let d = detector();
    d.load_dict(&[
        ("张三".to_string(), "name".to_string()),
        ("db-prod-01".to_string(), "hostname".to_string()),
    ]);
    // 标点分界命中（严格 CJK 边界：两侧非 CJK 字母数字）。
    let hits = d.scan_dict_sync("hi 张三，你好", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    // 张三丰不误伤（后接 CJK 即阻断，双模式一致）。
    let hits = d.scan_dict_sync("张三丰来了", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    // 非硬化：前接 CJK 按原仓口径放行（before 仅 ASCII 门）；
    // 硬化开：前接 CJK 阻断（严格 CJK 边界）。
    let hits = d.scan_dict_sync("我张三", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    d.set_hardening(true);
    let hits = d.scan_dict_sync("我张三", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    let hits = d.scan_dict_sync("hi 张三，你好", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    // 主机名 ASCII 粘连不命中。
    let hits = d.scan_dict_sync("abcdb-prod-01x", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "db-prod-01"));
    let hits = d.scan_dict_sync("主机 db-prod-01 在线", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "db-prod-01"));
}

#[test]
fn dict_boundary_nonhardened() {
    // P10/D11：非强化 `name/person` after 门仅 CJK 表意文字，西文变音字母数字不误拒。
    let d = detector();
    assert!(!d.hardening());
    d.load_dict(&[("张三".to_string(), "name".to_string())]);
    // `café张三`：字典名紧贴变音词（before='é' 非 ASCII）按 Python 非硬化口径保留。
    let hits = d.scan_dict_sync("café张三", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    // after 侧 `é`（非 CJK 表意）不得误拒，保 `张三é` 命中（收窄前会被 alnum 阻断）。
    let hits = d.scan_dict_sync("张三é", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    // 后接真正 CJK 仍阻断（保张三丰不误伤）。
    let hits = d.scan_dict_sync("张三丰", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
}

#[test]
fn dict_boundary() {
    let d = detector();
    d.load_dict(&[
        ("张三".to_string(), "name".to_string()),
        ("db-prod-01".to_string(), "hostname".to_string()),
    ]);
    // ASCII 粘连阻断：before 为 ASCII 字母数字。
    let hits = d.scan_dict_sync("Hi张三Done 来了", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    // CJK 紧贴阻断：after 为 CJK 表意文字。
    let hits = d.scan_dict_sync("张三丰来了", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    // 变音字母数字不误拒：`é`/`ñ` 紧贴任一模式均保留。
    for text in ["张三é", "é张三", "张三ñ", "ñ张三"] {
        let hits = d.scan_dict_sync(text, &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{text}: {hits:?}");
    }
    // 强化开：严格 CJK 双侧，变音字母数字亦阻断。
    d.set_hardening(true);
    let hits = d.scan_dict_sync("张三é", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    let hits = d.scan_dict_sync("张三丰", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
    // 非 name 类型仅挡 ASCII 粘连。
    let hits = d.scan_dict_sync("主机 db-prod-01 在线", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "db-prod-01"), "{hits:?}");
    let hits = d.scan_dict_sync("abcdb-prod-01x", &empty_cred());
    assert!(hits.iter().all(|h| h.1 != "db-prod-01"), "{hits:?}");
}

#[test]
fn named_group_inner_mismatch_uses_outer_name() {
    let d = detector();
    // 原仓口径：内命名组与外层失配允许加载（分类以外层 name 为准）。
    let n = d.load_custom_patterns(&[(
        "emp_no".to_string(),
        "(?P<other>(?<![\\d])AB\\d{6}(?![\\d]))".to_string(),
    )]);
    assert_eq!(n, 1, "内命名组失配按原仓口径放行");
    assert!(d.custom_names_snapshot().contains(&"emp_no".to_string()));
    let n = d.load_custom_patterns(&[("plain".to_string(), "ZZ-\\d{6}".to_string())]);
    assert_eq!(n, 1, "无命名组必须放行");
}

#[test]
fn nested_group_and_duplicate_name_rejected() {
    let d = detector();
    let n = d.load_custom_patterns(&[(
        "nested".to_string(),
        "(?P<nested>a(?P<inner>b)c)".to_string(),
    )]);
    assert_eq!(n, 0, "嵌套命名组必须拒绝");
    let n = d.load_custom_patterns(&[("dup".to_string(), "DUP-\\d+".to_string())]);
    assert_eq!(n, 1);
    let n = d.load_custom_patterns(&[("dup".to_string(), "DUP-\\d+".to_string())]);
    assert_eq!(n, 0, "跨文件重名必须去重拒绝");
    assert_eq!(
        d.custom_names_snapshot()
            .iter()
            .filter(|n| *n == "dup")
            .count(),
        1
    );
}

#[tokio::test]
async fn custom_overlap_placeholder_skipped_and_disabled_skipped() {
    let d = detector();
    d.load_custom_patterns(&[("tag".to_string(), "TAG-\\d+".to_string())]);
    let hits = d
        .scan_custom("已有 __PII_1_ab12cd34__ 与 TAG-99", &empty_cred())
        .await;
    assert!(hits.iter().any(|h| h.1 == "TAG-99"), "{hits:?}");
    let hits = d
        .scan_custom("data:image/png;base64,TAG-99", &empty_cred())
        .await;
    assert!(
        hits.is_empty(),
        "与 data URL 保护区间重叠必须跳过: {hits:?}"
    );
    d.account_rule("tag", true);
    d.account_rule("tag", true);
    d.account_rule("tag", true);
    assert!(d.disabled_snapshot().contains(&"tag".to_string()));
    let hits = d.scan_custom("TAG-77 独立出现", &empty_cred()).await;
    assert!(
        hits.iter().all(|h| h.0 != "tag"),
        "停用规则必须跳过: {hits:?}"
    );
}

#[tokio::test]
async fn custom_pattern_cjk_adjacent_match() {
    let d = detector();
    d.load_custom_patterns(&[(
        "工号".to_string(),
        "(?P<工号>(?<![\\d])工号\\d{6}(?![\\d]))".to_string(),
    )]);
    let hits = d.scan_custom("联系工号123456处理", &empty_cred()).await;
    assert!(
        hits.iter().any(|h| h.1 == "工号123456"),
        "CJK 紧贴必须命中: {hits:?}"
    );
}

#[test]
fn named_group_mismatch_relaxed_to_legacy() {
    let d = detector();
    // 内命名组与外层 name 不同名：原仓口径允许加载（分类以外层为准）。
    let n = d.load_custom_patterns(&[(
        "outer".to_string(),
        r"(?P<inner>(?<![\d])工号\d{6}(?![\d]))".to_string(),
    )]);
    assert_eq!(n, 1);
    assert!(d.custom_names_snapshot().contains(&"outer".to_string()));
}

#[test]
fn three_slot_custom_dict_combined() {
    let d = detector();
    let (n, m) = d.load_custom_all(
        &[(
            "emp_no".to_string(),
            r"(?<![\d])工号\d{6}(?![\d])".to_string(),
        )],
        &[("张三".to_string(), "name".to_string())],
    );
    assert_eq!((n, m), (1, 1));
    let hits = d.scan_dict_sync("hi 张三，工号123456", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
}

#[test]
fn dict_scan_excluded_from_combined_regex() {
    let d = detector();
    d.load_dict(&[("张三".to_string(), "name".to_string())]);
    // 联合正则扫描不含字典命中（独立扫描语义）。
    let builtin = super::super::chunk::scan_builtin_sync("hi 张三，你好", &empty_cred());
    assert!(builtin.iter().all(|h| h.1 != "张三"), "{builtin:?}");
    let dict = d.scan_dict_sync("hi 张三，你好", &empty_cred());
    assert!(dict.iter().any(|h| h.1 == "张三"), "{dict:?}");
}

#[test]
fn perf_5000_dict_scan_time_anchor() {
    let d = detector();
    let entries: Vec<(String, String)> = (0..5000)
        .map(|i| (format!("敏感词{i:05}号"), "name".to_string()))
        .collect();
    let start = std::time::Instant::now();
    d.load_dict(&entries);
    let text = "公告 敏感词01234号 与 敏感词04999号 上线";
    let hits = d.scan_dict_sync(text, &empty_cred());
    let elapsed = start.elapsed();
    assert!(
        hits.iter().any(|h| h.1 == "敏感词01234号"),
        "5000 字典首段须命中: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.1 == "敏感词04999号"),
        "5000 字典尾段须命中: {hits:?}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "5000 字典加载+扫描须 <10s，实测 {elapsed:?}"
    );
}

#[tokio::test]
async fn pii_lock_poison_scan_no_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let d = detector();
    d.load_custom_patterns(&[("tag".to_string(), r"TAG-\d+".to_string())]);
    d.load_dict(&[("张三".to_string(), "name".to_string())]);
    // 逐把锁持锁 panic 毒化（含 disabled/strikes 两把 Mutex）。
    let poisoners: [fn(&super::PiiDetector); 6] = [
        |x| {
            let _g = x.custom.write().unwrap();
            panic!("poison custom");
        },
        |x| {
            let _g = x.custom_names.write().unwrap();
            panic!("poison custom_names");
        },
        |x| {
            let _g = x.strikes.lock().unwrap();
            panic!("poison strikes");
        },
        |x| {
            let _g = x.disabled.lock().unwrap();
            panic!("poison disabled");
        },
        |x| {
            let _g = x.dict.write().unwrap();
            panic!("poison dict");
        },
        |x| {
            let _g = x.dict_re.write().unwrap();
            panic!("poison dict_re");
        },
    ];
    for poison in poisoners {
        let _ = catch_unwind(AssertUnwindSafe(|| poison(&d)));
    }
    let hits = d.scan_dict_sync("hi 张三，你好", &empty_cred());
    assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    let hits = d.scan_custom("TAG-99", &empty_cred()).await;
    assert!(hits.iter().any(|h| h.1 == "TAG-99"), "{hits:?}");
    d.account_rule("tag", true);
    assert!(d.custom_names_snapshot().contains(&"tag".to_string()));
    assert!(!d.disabled_snapshot().contains(&"tag".to_string()));
}

#[tokio::test]
async fn pii_lock_poison_recovery() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let d = detector();
    d.load_custom_patterns(&[("tag".to_string(), r"TAG-\d+".to_string())]);
    let baseline = d.scan_custom("TAG-99 与 TAG-7", &empty_cred()).await;
    let poisoners: [fn(&super::PiiDetector); 2] = [
        |x| {
            let _g = x.custom.write().unwrap();
            panic!("poison custom");
        },
        |x| {
            let _g = x.custom_names.write().unwrap();
            panic!("poison custom_names");
        },
    ];
    for poison in poisoners {
        let _ = catch_unwind(AssertUnwindSafe(|| poison(&d)));
    }
    let after = d.scan_custom("TAG-99 与 TAG-7", &empty_cred()).await;
    assert_eq!(after, baseline, "中毒恢复结果须与未中毒基线一致");
    let n = d.load_custom_patterns(&[("healed".to_string(), r"HEAL-\d+".to_string())]);
    assert_eq!(n, 1, "中毒后 load 须自愈注入新规则");
    let hits = d.scan_custom("HEAL-42", &empty_cred()).await;
    assert!(hits.iter().any(|h| h.1 == "HEAL-42"), "{hits:?}");
    // warn 一次性：隔离标志位断言（全局标志位被并行用例抢占，不作断言依据）。
    let flag = std::sync::atomic::AtomicBool::new(false);
    assert!(
        crate::service::lock_recover::warn_poison_once_at(&flag),
        "首次恢复须告警"
    );
    assert!(
        !crate::service::lock_recover::warn_poison_once_at(&flag),
        "重复恢复仅 warn 一次"
    );
}

#[test]
fn partial_prefix_hints_cap_desc_dedup_and_dict() {
    let d = detector();
    let long = "A".repeat(80);
    d.load_custom_patterns(&[
        ("tag".to_string(), r"TAG-\d+".to_string()),
        (
            "cjk".to_string(),
            r"(?P<cjk>(?<![\d])工号\d{6}(?![\d]))".to_string(),
        ),
        ("class".to_string(), r"[A-Z]\d+".to_string()),
        ("long".to_string(), format!(r"{long}\d+")),
    ]);
    d.load_dict(&[
        ("张三".to_string(), "name".to_string()),
        ("张三".to_string(), "person".to_string()),
    ]);
    let hints = d.partial_prefix_hints();
    assert!(hints.contains(&"TAG-".to_string()), "{hints:?}");
    assert!(hints.contains(&"工号".to_string()), "{hints:?}");
    assert!(
        hints.contains(&"张三".to_string()),
        "字典全名须在内: {hints:?}"
    );
    assert!(hints.iter().all(|h| h.chars().count() <= 64), "{hints:?}");
    assert!(
        hints.contains(&"A".repeat(64)),
        "超长前缀须截断到 64: {hints:?}"
    );
    assert!(
        !hints.iter().any(|h| h.starts_with('[')),
        "字符类无可提取字面前缀: {hints:?}"
    );
    let lens: Vec<usize> = hints.iter().map(|h| h.chars().count()).collect();
    assert!(
        lens.windows(2).all(|w| w[0] >= w[1]),
        "须长度降序: {hints:?}"
    );
    let mut uniq = hints.clone();
    uniq.dedup();
    assert_eq!(uniq, hints, "hint 须去重: {hints:?}");
}

#[test]
fn prefix_hints_capped_64() {
    // APP-6（4.15）：hint 集合总条数上限 64（去重后按长度降序保留前 64）。
    let d = detector();
    let rules: Vec<(String, String)> = (0..80)
        .map(|i| (format!("p{i:02}"), format!("PREFIX{i:02}-\\d+")))
        .collect();
    let n = d.load_custom_patterns(&rules);
    assert_eq!(n, 80, "80 条规则须全部加载");
    let hints = d.partial_prefix_hints();
    assert_eq!(hints.len(), 64, "hint 总条数须截断至 64: {}", hints.len());
    // 各前缀等长，按 (长度降序, 字典序) 保留前 64——最长前缀集合内有界。
    assert!(
        hints.contains(&"PREFIX00-".to_string()),
        "保留集须含最优前缀: {hints:?}"
    );
    assert!(
        !hints.contains(&"PREFIX79-".to_string()),
        "超出 64 条的前缀须被截断: {hints:?}"
    );
    let mut uniq = hints.clone();
    uniq.dedup();
    assert_eq!(uniq, hints, "hint 须去重: {hints:?}");
}

#[test]
fn regex_literal_prefix_extraction_rules() {
    assert_eq!(super::regex_literal_prefix(r"TAG-\d+"), "TAG-");
    assert_eq!(
        super::regex_literal_prefix(r"(?P<cjk>(?<![\d])工号\d{6}(?![\d]))"),
        "工号"
    );
    assert_eq!(super::regex_literal_prefix(r"(?:abc|def)\d"), "abc");
    assert_eq!(super::regex_literal_prefix(r"[A-Z]\d+"), "");
    assert_eq!(super::regex_literal_prefix(r"^(a+)+$"), "a");
    assert_eq!(super::regex_literal_prefix(r"a\.b\-c"), "a.b-c");
}

#[tokio::test]
async fn scan_custom_batch_equivalence() {
    // ARH-4（7.3）：单任务批量扫描与逐规则逐分块结果等价；停用规则仍被跳过。
    use std::collections::HashSet;
    let d = detector();
    d.load_custom_patterns(&[
        ("tag".to_string(), r"TAG-\d+".to_string()),
        ("emp".to_string(), r"工号\d{6}".to_string()),
    ]);
    let hits = d
        .scan_custom("A TAG-11 工号123456 B TAG-22", &empty_cred())
        .await;
    let got: HashSet<(String, String)> = hits
        .iter()
        .map(|(k, v, ..)| (k.clone(), v.clone()))
        .collect();
    assert!(
        got.contains(&("tag".to_string(), "TAG-11".to_string())),
        "{hits:?}"
    );
    assert!(
        got.contains(&("tag".to_string(), "TAG-22".to_string())),
        "{hits:?}"
    );
    assert!(
        got.contains(&("emp".to_string(), "工号123456".to_string())),
        "{hits:?}"
    );
    assert_eq!(hits.len(), 3, "命中须与逐规则扫描一致: {hits:?}");
    d.account_rule("tag", true);
    d.account_rule("tag", true);
    d.account_rule("tag", true);
    let hits = d.scan_custom("TAG-33 工号999999", &empty_cred()).await;
    assert!(
        hits.iter().all(|h| h.0 != "tag"),
        "停用规则须跳过: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.0 == "emp"),
        "他规则不受影响: {hits:?}"
    );
}
