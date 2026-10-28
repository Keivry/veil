//! `Scope` 请求/响应编排单测（自 `scope.rs` 拆出；测试名与断言不变）。

mod conversation_scope;
mod redaction_tally;
mod strip_partials_hardening;
mod strip_partials_limits;
mod strip_partials_reorder_differential;

use {
    super::{test_support::mint_cred, *},
    crate::service::pii::apply_spans,
};

fn vault_with_secret(secret: &str) -> CredentialVault {
    let v = CredentialVault::new();
    v.register(secret).unwrap();
    v
}

#[tokio::test]
async fn request_redact_response_restore() {
    let vault = vault_with_secret("my-secret-001");
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let req = r#"{"pwd":"my-secret-001","phone":"13812345678"}"#;
    let redacted = scope.redact_request(&vault, &detector, req).await;
    assert!(!redacted.contains("my-secret-001"), "{redacted}");
    assert!(!redacted.contains("13812345678"), "{redacted}");
    assert!(redacted.contains("__CRED_"), "{redacted}");
    assert!(redacted.contains("__PII_"), "{redacted}");
    // JSON 语义等价：仍可解析，键名层级不变。
    let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
    assert!(v.get("pwd").is_some() && v.get("phone").is_some());
    let restored = scope.restore_response(&vault, &redacted);
    assert!(restored.contains("my-secret-001"), "{restored}");
    assert!(restored.contains("13812345678"), "{restored}");
}

#[tokio::test]
async fn same_secret_reuse_single_register_rebuild_consistent() {
    let vault = vault_with_secret("cache-secret-xyz");
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let req = r#"{"a":"cache-secret-xyz","b":"cache-secret-xyz"}"#;
    let once = scope.redact_request(&vault, &detector, req).await;
    let twice = scope.redact_request(&vault, &detector, req).await;
    assert_eq!(once, twice, "同秘密重复脱敏须复用一致");
    assert_eq!(vault.len(), 1, "同一秘密只注册一次");
    // 重建一致：还原后结构与原文一致。
    let rebuilt = scope.restore_response(&vault, &once);
    let v_orig: serde_json::Value = serde_json::from_str(req).unwrap();
    let v_back: serde_json::Value = serde_json::from_str(&rebuilt).unwrap();
    assert_eq!(v_orig, v_back);
}

#[tokio::test]
async fn cross_request_pii_not_restorable() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let a = Scope::new();
    let b = Scope::new();
    let redacted = a
        .redact_request(&vault, &detector, "电话 13812345678")
        .await;
    assert!(redacted.contains("__PII_"));
    // B 持有 A 的占位符：还原失败；未注册完整 token 原样透传（不还原、不移除）。
    let restored_by_b = b.restore_response(&vault, &redacted);
    assert!(
        restored_by_b.contains("__PII_"),
        "未注册完整 token 须原样透传: {restored_by_b}"
    );
    assert!(!restored_by_b.contains("13812345678"));
}

#[tokio::test]
async fn nested_tool_calls_roundtrip() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let req = r#"{"tool_calls":[{"name":"login","arguments":"{\"user\":\"admin\",\"key\":\"p@ss\\\"quote\",\"code\":\"\\u0031\"}"}]}"#;
    let redacted = scope.redact_request(&vault, &detector, req).await;
    // 无 PII/凭据命中时结构原样（roundtrip 保证可解析）。
    let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
    let args: serde_json::Value =
        serde_json::from_str(v["tool_calls"][0]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(args["key"], "p@ss\"quote");
    assert_eq!(args["code"], "1");
}

#[tokio::test]
async fn nonstream_and_stream_tail_partials_cleaned() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    // 残缺前缀在出口被清理，不泄漏半截占位符。
    let dirty = "正文 __CRED_000 与 __PII_2_ab 结尾";
    let cleaned = scope.redact_request_plain(&vault, &detector, dirty).await;
    assert!(!cleaned.contains("__CRED_000"), "{cleaned}");
    assert!(!cleaned.contains("__PII_2_ab"), "{cleaned}");
    let restored = scope.restore_response(&vault, "ok __CRED_12");
    assert!(!restored.contains("__CRED_12"), "{restored}");
}

#[tokio::test]
async fn three_wrappers_nasty_scope_paths() {
    // 含引号密码、
    // Unicode 转义、嵌套 stringified JSON、数组成员经三条 JSON-aware 路径
    // （① token 脱敏/还原 ② PII 脱敏 ③ LLM 响应还原）后输出恒可解析且值一致。
    let vault = CredentialVault::new();
    let secret = "p@ss\"quote";
    let detector = PiiDetector::new();
    let nasty = serde_json::json!({
        "pwd": secret,
        "uni": "\u{61}1b",
        "nested": serde_json::to_string(&serde_json::json!({"k":"v1"})).unwrap(),
        "list": ["x", "y"],
    });
    let raw = serde_json::to_string(&nasty).unwrap();
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();

    // ① token 脱敏：凭据值替换为 `__CRED_` token。
    let redacted = scope.redact_request(&vault, &detector, &raw).await;
    let rv: serde_json::Value = serde_json::from_str(&redacted).expect("脱敏输出须合法 JSON");
    assert!(
        rv["pwd"].as_str().is_some_and(|s| s.starts_with("__CRED_")),
        "{redacted}"
    );
    assert_eq!(rv["uni"], "a1b", "Unicode 转义须解码正确");
    assert_eq!(rv["list"][0], "x");
    let nested: serde_json::Value =
        serde_json::from_str(rv["nested"].as_str().expect("nested 为字符串"))
            .expect("嵌套 JSON 须完好");
    assert_eq!(nested["k"], "v1");

    // ①b token 还原：JSON 字符串上下文还原（RFC 8259 转义）后输出合法且值一致。
    let (restored, _) = scope.restore_response_with_spans_json(&vault, &redacted);
    let sv: serde_json::Value = serde_json::from_str(&restored).expect("还原输出须合法 JSON");
    assert_eq!(sv["pwd"], secret);

    // ② PII 脱敏：新检出以 `__PII_` 占位符呈现且输出可解析。
    let pii_raw = serde_json::to_string(&serde_json::json!({"phone":"13812345678"})).unwrap();
    let pii_out = scope.redact_request(&vault, &detector, &pii_raw).await;
    let pv: serde_json::Value = serde_json::from_str(&pii_out).expect("PII 脱敏输出须合法 JSON");
    assert!(
        pv["phone"]
            .as_str()
            .is_some_and(|s| s.starts_with("__PII_")),
        "{pii_out}"
    );

    // ③ LLM 响应还原：token 出现在 JSON 字符串内被还原。
    let frame = serde_json::to_string(&serde_json::json!({"msg": format!("hi {token}")})).unwrap();
    let (llm_out, _) = scope.restore_response_with_spans_json(&vault, &frame);
    let lv: serde_json::Value = serde_json::from_str(&llm_out).expect("响应还原输出须合法 JSON");
    assert_eq!(lv["msg"], format!("hi {secret}"));
}

#[test]
fn fuzzy_case_drift_exact_vs_sequence_lookup() {
    // `PII_FUZZY_RESTORE` 关闭时大小写漂移不还原（精确原样保留），
    // 开启时按序号回查还原。`__PII_<seq>_ZZZZABCD__` 为大写非 hex 漂移形。
    let vault = CredentialVault::new();
    let plain = "13812345678";
    let exact = Scope::with_opts(false);
    let token = exact.pii_scope().register(plain).expect("注册恒成功");
    let seq: usize = token
        .strip_prefix("__PII_")
        .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
        .flatten()
        .expect("token 恒带序号");
    let case_drift = format!("__PII_{seq}_ZZZZABCD__");
    // 关闭：大小写漂移不还原，原样保留。
    let out = exact.restore_response(&vault, &format!("回拨 {case_drift} 结束"));
    assert!(out.contains(&case_drift), "关闭态须原样保留: {out}");
    assert!(!out.contains(plain), "关闭态不得还原: {out}");
    // 开启：按序号回查还原。
    let fuzzy = Scope::with_opts(true);
    let token2 = fuzzy.pii_scope().register(plain).expect("注册恒成功");
    let seq2: usize = token2
        .strip_prefix("__PII_")
        .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
        .flatten()
        .expect("token 恒带序号");
    let out2 = fuzzy.restore_response(&vault, &format!("回拨 __PII_{seq2}_ZZZZABCD__ 结束"));
    assert!(out2.contains(plain), "开启态须还原: {out2}");
    assert!(!out2.contains("__PII_"), "还原后不留 token: {out2}");
}

#[test]
fn fuzzy_restore_by_sequence_lookup() {
    let vault = CredentialVault::new();
    let plain = "13812345678";
    let exact = Scope::with_opts(false);
    let token = exact.pii_scope().register(plain).unwrap();
    let seq: usize = token
        .strip_prefix("__PII_")
        .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
        .flatten()
        .expect("token 恒带序号");
    let fuzzy_tok = format!("__PII_{seq}_zzzz__");
    // 精确模式保留宽松形态。
    assert!(
        exact
            .restore_response(&vault, &format!("回拨 {fuzzy_tok}"))
            .contains(&fuzzy_tok)
    );
    // 宽松模式按序号还原明文。
    let scope2 = Scope::with_opts(true);
    let token2 = scope2.pii_scope().register(plain).unwrap();
    let seq2: usize = token2
        .strip_prefix("__PII_")
        .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
        .flatten()
        .unwrap();
    let restored = scope2.restore_response(&vault, &format!("回拨 __PII_{seq2}_zzzz__"));
    assert!(restored.contains(plain), "{restored}");
    assert!(!restored.contains("__PII_"), "{restored}");
}

#[test]
fn strip_partials_legal_text_untouched() {
    // 合法正文前缀续段/单词字符逐字节不变（不得误删）。
    for legal in [
        "__CREDENTIALS",
        "__CUSTOMER",
        "__CREDIT",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文不得误删: {legal}");
    }
    // 真残缺仍被清理（保护不退化）。
    for partial in ["__C", "__CRED_000", "__PII_3_ab"] {
        let cleaned = strip_partials(partial);
        assert!(!cleaned.contains("__C"), "{partial} -> {cleaned:?}");
        assert!(!cleaned.contains("__PI"), "{partial} -> {cleaned:?}");
    }
}

#[test]
fn strip_partials_differential() {
    // 差分用例表（合法正文 vs 真残缺 vs 前缀本身），逐条锁定边界。
    for legal in [
        "__CREDENTIALS",
        "__CUSTOMER",
        "__CREDIT",
        "__CREDX",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
        "__CRED_000extra",
        "__PII_3_abzz",
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文须不变: {legal}");
    }
    for partial in [
        "__C",
        "__C_",
        "__CR",
        "__CRE",
        "__CRED",
        "__CRED_",
        "__CRED_000",
        "__CRED_000001",
        "__PI",
        "__PI_",
        "__PII",
        "__PII_",
        "__PII__",
        "__PII_3",
        "__PII_3_",
        "__PII_3_ab",
    ] {
        let out = strip_partials(partial);
        assert!(out.is_empty(), "真残缺/前缀须剥净: {partial:?} -> {out:?}");
    }
    // 完整形态口径：凭据与 PII 完整形态均由负向前瞻豁免，原样保留。
    assert_eq!(strip_partials("__CRED_000001__"), "__CRED_000001__");
    assert!(
        strip_partials("__PII_1_ab12cd34__").contains("__PII_1_ab12cd34__"),
        "PII 完整形态须保留"
    );
    // 尾随边界（空白）剥离，后随合法单词字符不剥离。
    assert_eq!(strip_partials("尾部 __CRED_12 结束"), "尾部  结束");
    assert_eq!(
        strip_partials("正文 __PII_2_ab 结束"),
        "正文  结束",
        "残缺后随空白须剥离"
    );
}

#[test]
fn strip_partial_and_complete_fn_semantics() {
    assert_eq!(strip_partials("a __CRED_00 b"), "a  b");
    assert_eq!(strip_partials("a __PII_3_ab b"), "a  b");
    // 完整形态原样保留（不误剥）。
    assert_eq!(strip_partials("x __CRED_123456__ y"), "x __CRED_123456__ y");
    assert!(strip_partials("x __PII_1_ab12cd34__ y").contains("__PII_1_ab12cd34__"));
}

#[test]
fn strip_partials_cross_family_complete_token_kept() {
    // 完整 token 闭合 `__` + 后随残缺前缀字符：完整 token 与字面字符均保留。
    assert_eq!(
        strip_partials("B__PII_1_2adda239__C"),
        "B__PII_1_2adda239__C"
    );
    assert_eq!(strip_partials("__CRED_000123__PI"), "__CRED_000123__PI");
    // 跨族真残缺仍剥（4 下划线）：完整 token 留住、异族残片剥净。
    assert_eq!(
        strip_partials("__PII_1_ab12cd34____CRED_000"),
        "__PII_1_ab12cd34__"
    );
}

#[test]
fn skip_sentinel_tail_is_partial_immune() {
    // 哨兵产物尾字符恒非 `_`，`<哨兵>C`/`<哨兵>PI` 不被残缺清理误剥。
    for suffix in ["C", "PI"] {
        let s = format!("{}{suffix}", skip_sentinel(0, ""));
        assert_eq!(strip_partials(&s), s, "哨兵免疫: {s}");
    }
    // 碰撞消解追加非 `_`：产物仍不以 `_` 结尾且免疫（旧 `_` 追加会追加出尾 `__` 致腐蚀）。
    let base = skip_sentinel(0, "");
    let collided = skip_sentinel(0, &base);
    assert_ne!(collided, base);
    assert!(!collided.ends_with('_'));
    let s = format!("{collided}C");
    assert_eq!(strip_partials(&s), s, "碰撞哨兵免疫: {s}");
}

#[tokio::test]
async fn request_side_token_adjacent_c_preserved() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let out = scope
        .redact_request_plain(&vault, &detector, "B13812345678C")
        .await;
    assert!(!out.contains("13812345678"), "PII 须脱敏: {out}");
    assert!(out.contains("__PII_"), "须含占位符: {out}");
    assert!(out.starts_with('B'), "前缀 B 须保留: {out}");
    assert!(out.ends_with('C'), "后随字面 C 须保留: {out}");
}

#[tokio::test]
async fn response_side_token_adjacent_c_restored_without_sentinel_leak() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let token = scope
        .redact_request_plain(&vault, &detector, "13812345678")
        .await;
    assert!(token.starts_with("__PII_"), "须铸造占位符: {token}");
    // 上游回显占位符后紧跟字面 C：须还原为 13812345678C，零哨兵/占位符残留。
    let (restored, spans) = scope.restore_response_with_spans(&vault, &format!("{token}C"));
    assert_eq!(restored, "13812345678C", "须还原且保留 C: {restored}");
    assert!(!restored.contains("__VEILSKIP"), "哨兵不得泄漏: {restored}");
    assert!(!restored.contains("__PII_"), "占位符不得残留: {restored}");
    assert_eq!(spans, vec![(0, 11)], "还原 span 须覆盖明文");
}

#[tokio::test]
async fn multiline_faithful_roundtrip_bytes_identical() {
    let vault = vault_with_secret("my-secret-001");
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let req = "第一行 电话 13812345678 📞\n第二行 密钥 my-secret-001 ✅\n第三行 纯文本无敏感";
    let redacted = scope.redact_request_plain(&vault, &detector, req).await;
    assert!(!redacted.contains("13812345678"), "{redacted}");
    assert!(!redacted.contains("my-secret-001"), "{redacted}");
    assert!(redacted.contains("第三行 纯文本无敏感"), "{redacted}");
    let restored = scope.restore_response(&vault, &redacted);
    assert_eq!(restored, req, "往返须字节一致");
}

#[tokio::test]
async fn restore_spans_cover_plaintext_location() {
    // 还原 span 逐出现点定位：仅 token 出现点进入 span 区间。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let redacted = scope
        .redact_request(&vault, &detector, r#"{"phone":"13812345678"}"#)
        .await;
    assert!(redacted.contains("__PII_"), "{redacted}");
    let (restored, spans) = scope.restore_response_with_spans(&vault, &redacted);
    assert!(restored.contains("13812345678"), "{restored}");
    assert!(
        spans
            .iter()
            .any(|(s, e)| &restored[*s..*e] == "13812345678"),
        "{spans:?}"
    );
}

#[tokio::test]
async fn credential_restore_spans_cover_plaintext() {
    let vault = CredentialVault::new();
    vault.register("my-secret-001").expect("注册恒成功");
    let scope = Scope::new();
    let masked = scope
        .redact_request(&vault, &PiiDetector::new(), "密码 my-secret-001 结束")
        .await;
    assert!(!masked.contains("my-secret-001"), "{masked}");
    let (restored, spans) = scope.restore_response_with_spans(&vault, &masked);
    assert_eq!(restored, "密码 my-secret-001 结束");
    assert_eq!(spans.len(), 1);
    assert_eq!(&restored[spans[0].0..spans[0].1], "my-secret-001");
    // 未知 token 不产生 span。
    let (unchanged, empty) = scope.restore_response_with_spans(&vault, "纯文本无 token");
    assert_eq!(unchanged, "纯文本无 token");
    assert!(empty.is_empty());
}

#[tokio::test]
async fn per_token_lookup_does_not_snapshot_full_vault() {
    let vault = CredentialVault::new();
    let secret = "complexity-secret-001";
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let text = format!("{token} {token} {token}");
    let before = vault.snapshot_calls();
    let (restored, spans) = scope.restore_response_with_spans(&vault, &text);
    assert_eq!(restored, format!("{secret} {secret} {secret}"));
    assert_eq!(spans.len(), 3);
    // 主还原与 span 回查均逐 token 直查，全量快照计数零增量。
    assert_eq!(
        vault.snapshot_calls() - before,
        0,
        "逐 token 直查不得触发全表克隆（含主还原路径）"
    );
}

#[tokio::test]
async fn restore_per_token_parity() {
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let a = vault.register("parity-secret-alpha").unwrap();
    let b = vault.register("parity-secret-beta").unwrap();
    mint_cred(&scope, &vault, "parity-secret-alpha parity-secret-beta").await;
    let pii_tok = scope.pii_scope().register("13812345678").unwrap();
    let sample = format!(
        "{{\"x\":\"{a}{b}\",\"y\":\"__CRED_999999__\",\"z\":\"{pii_tok}\",\"e\":\"换行\\n引号\\\"\"}}"
    );
    let per_token = scope.restore_response(&vault, &sample);
    let full = {
        let step1 = vault.restore(&sample);
        let step2 = scope.pii_scope().restore(&step1);
        strip_partials(&step2)
    };
    assert_eq!(per_token, full, "逐 token 还原须与全量路径逐字节一致");
    assert!(per_token.contains("parity-secret-alpha"), "{per_token}");
    assert!(per_token.contains("parity-secret-beta"), "{per_token}");
    assert!(
        per_token.contains("__CRED_999999__"),
        "未注册完整 token 原样透传: {per_token}"
    );
    assert!(per_token.contains("13812345678"), "{per_token}");
}

#[test]
fn span_apply_dedup_semantics() {
    let out = apply_spans(
        "hello world",
        &[(6, 11, "W".to_string()), (6, 11, "W".to_string())],
        true,
    );
    assert_eq!(out, "hello W");
}

#[test]
fn restore_idempotent_unregistered_passthrough() {
    let vault = vault_with_secret("my-secret-001");
    let scope = Scope::new();
    let tok = scope.pii_scope().register("13812345678").unwrap();
    let mixed = format!("回拨 {tok} 与 __PII_9_ab12cd34__ 及 my-secret-001");
    let once = scope.restore_response(&vault, &mixed);
    assert!(once.contains("13812345678"), "{once}");
    // 未注册完整 token 原样透传（不再遮蔽）。
    assert!(
        once.contains("__PII_9_ab12cd34__"),
        "未注册完整 token 须原样透传: {once}"
    );
    assert!(once.contains("my-secret-001"), "明文直通不改写: {once}");
    let twice = scope.restore_response(&vault, &once);
    assert_eq!(twice, once, "二次还原须与一次一致");
}

#[tokio::test]
async fn dict_5000_no_combined_regex_blowup_time_anchor() {
    let detector = PiiDetector::new();
    let dict: Vec<(String, String)> = (0..5000)
        .map(|i| (format!("合成姓名{i:05}号"), "name".to_string()))
        .collect();
    detector.load_dict(&dict);
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let text = "正文含 合成姓名01234号 ok 与其余文字混合".to_string();
    let start = std::time::Instant::now();
    let out = scope.redact_request(&vault, &detector, &text).await;
    let elapsed = start.elapsed();
    assert!(!out.contains("合成姓名01234号"), "{out}");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "5000 字典单次扫描须远低于宽松上界（防 13.8ms 爆炸回归），实测 {elapsed:?}"
    );
}

#[tokio::test]
async fn incremental_scan_time_anchor_loose_bound() {
    let vault = vault_with_secret("anchor-secret-007");
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let start = std::time::Instant::now();
    for i in 0..100 {
        let text = format!("{{\"k{i}\":\"v{i} anchor-secret-007 13812345678\"}}");
        let out = scope.redact_request(&vault, &detector, &text).await;
        assert!(!out.contains("anchor-secret-007"), "{out}");
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(30),
        "100 次增量扫描须远低于宽松上界，实测 {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn scope_request_isolation_concurrent_invisible() {
    let detector = std::sync::Arc::new(PiiDetector::new());
    let mut handles = Vec::new();
    for i in 0..4 {
        let d = std::sync::Arc::clone(&detector);
        handles.push(tokio::spawn(async move {
            let vault = CredentialVault::new();
            let secret = format!("隔离密钥-{i:02}");
            vault.register(&secret).unwrap();
            let scope = Scope::new();
            let text = format!("{{\"s\":\"{secret}\"}}");
            scope.redact_request(&vault, &d, &text).await
        }));
    }
    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("隔离任务不得失败"));
    }
    for (i, out) in outs.iter().enumerate() {
        for j in 0..4 {
            assert!(
                !out.contains(&format!("隔离密钥-{j:02}")),
                "scope{i} 不得透出任何明文密钥（含自身注册前形态）: {out}"
            );
        }
    }
}

#[tokio::test]
async fn t12_scope_registration_isolated_across_tasks() {
    let vault = std::sync::Arc::new(CredentialVault::new());
    let detector = std::sync::Arc::new(PiiDetector::new());
    let a = tokio::spawn({
        let (vault, detector) = (vault.clone(), detector.clone());
        async move {
            let scope = Scope::new();
            scope
                .redact_request(&vault, &detector, "号码 13800138000 结束")
                .await
        }
    });
    let b = tokio::spawn({
        let (vault, detector) = (vault.clone(), detector.clone());
        async move {
            let scope = Scope::new();
            scope
                .redact_request(&vault, &detector, "号码 13800138000 结束")
                .await
        }
    });
    let (out_a, out_b) = tokio::join!(a, b);
    let (out_a, out_b) = (out_a.expect("任务 A 须成功"), out_b.expect("任务 B 须成功"));
    assert!(out_a.contains("__PII_"), "A 须脱敏");
    assert!(out_b.contains("__PII_"), "B 须脱敏");
    assert_ne!(out_a, out_b, "独立 Scope 的 rand8 须不同（请求隔离）");
}

#[test]
fn t12_restore_only_own_scope_tokens() {
    let vault = CredentialVault::new();
    let scope_a = Scope::new();
    let scope_b = Scope::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("单线程运行时须可用");
    let out_a =
        rt.block_on(scope_a.redact_request(&vault, &PiiDetector::new(), "号码 13800138000 结束"));
    let out_b =
        rt.block_on(scope_b.redact_request(&vault, &PiiDetector::new(), "号码 13800138000 结束"));
    assert_ne!(out_a, out_b);
    // 跨 Scope 的他方 token 未注册，出口原样透传（不还原、不移除）。
    assert!(scope_a.restore_response(&vault, &out_b).contains("__PII_"));
    assert!(scope_b.restore_response(&vault, &out_a).contains("__PII_"));
    assert!(
        scope_a
            .restore_response(&vault, &out_a)
            .contains("13800138000")
    );
}

#[tokio::test]
async fn nested_stringified_json_restore_inner_valid() {
    // 两层嵌套 stringified JSON 参数内含带引号凭据明文，还原写回须按
    // 实际 JSON 深度转义，内层结构保持有效、无非法裸 `"`。
    let vault = CredentialVault::new();
    let secret = "p@ss\"q";
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let frame = serde_json::to_string(&serde_json::json!({
        "arguments": serde_json::to_string(&serde_json::json!({ "k": token })).unwrap()
    }))
    .unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert!(restored.contains("p@ss"), "{restored}");
    assert!(!restored.contains(&token), "token 须还原: {restored}");
    assert!(!spans.is_empty());
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("还原后外层须合法 JSON");
    let inner_raw = outer["arguments"].as_str().expect("arguments 为字符串");
    let inner: serde_json::Value =
        serde_json::from_str(inner_raw).expect("还原后内层 stringified JSON 须可解析");
    assert_eq!(inner["k"], secret);
    assert!(
        !inner_raw.contains("\"p@ss\"q\""),
        "内层不得裸写未转义引号: {inner_raw}"
    );
}

#[tokio::test]
async fn restore_json_aware_regression() {
    // 回归：单层帧仅命中 span 单层转义、其余字节等价；零替换帧不触发
    // `loads→dumps` 重排（逐字节透传）。
    let vault = CredentialVault::new();
    let secret = "p@ss\"q";
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let single = format!("{{\"msg\":\"hi {token}\"}}");
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &single);
    assert_eq!(restored, "{\"msg\":\"hi p@ss\\\"q\"}");
    assert_eq!(spans.len(), 1);
    let zero = r#"{"b":2,"a":1e3}"#;
    let (out, zero_spans) = scope.restore_response_with_spans_json(&vault, zero);
    assert_eq!(out, zero, "零替换须逐字节透传");
    assert!(zero_spans.is_empty());
}

fn vault_with(secret: &str) -> (CredentialVault, String) {
    let vault = CredentialVault::new();
    let token = vault.register(secret).unwrap();
    (vault, token)
}

#[tokio::test]
async fn pii_unavailable_flag_set_on_entropy_failure() {
    // 注入 rand8 熵源故障 → 脱敏链失败信号置位，调用方据此 fail-closed。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    scope.pii_scope().force_entropy_failure(true);
    let redacted = scope
        .redact_request(&vault, &detector, r#"{"phone":"13812345678"}"#)
        .await;
    assert!(scope.pii_unavailable(), "熵源故障须置 fail-closed 信号");
    assert!(redacted.contains("13812345678"), "本层不做替换: {redacted}");
    // token 形态值：静默跳过，不置失败信号、不报错。
    let scope2 = Scope::new();
    let out = scope2
        .redact_request(&vault, &detector, r#"{"p":"__PII_1_ab12cd34__"}"#)
        .await;
    assert!(!scope2.pii_unavailable(), "token 形态不得置失败信号");
    assert!(
        out.contains("__PII_1_ab12cd34__"),
        "token 形态原样保留: {out}"
    );
}

#[tokio::test]
async fn same_plaintext_cross_depth_escape() {
    // 同明文跨深度逐点转义——浅层不得按深层 max 过度转义（内容损坏）。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let inner = serde_json::to_string(&serde_json::json!({ "k": token })).unwrap();
    let frame = serde_json::to_string(&serde_json::json!({ "a": token, "b": inner })).unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert_eq!(spans.len(), 2, "两个出现点各一 span: {spans:?}");
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("还原后外层须合法");
    assert_eq!(outer["a"], secret, "浅层出现点不得被过度转义: {restored}");
    let inner_parsed: serde_json::Value =
        serde_json::from_str(outer["b"].as_str().expect("b 为字符串")).expect("内层须可解析");
    assert_eq!(
        inner_parsed["k"], secret,
        "深层出现点须正确转义: {restored}"
    );
}

#[tokio::test]
async fn escape_per_occurrence() {
    // 各出现点按自身深度转义，互不聚合。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let lvl2 = serde_json::to_string(&serde_json::json!({ "k": token })).unwrap();
    let frame = serde_json::to_string(&serde_json::json!({ "a": token, "b": lvl2 })).unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("外层须合法");
    assert_eq!(outer["a"], secret);
    let inner_parsed: serde_json::Value =
        serde_json::from_str(outer["b"].as_str().unwrap()).expect("内层须合法");
    assert_eq!(inner_parsed["k"], secret);
    assert_eq!(spans.len(), 2);
}

#[tokio::test]
async fn key_depth_escape() {
    // 对象 key 位凭据深度须计入，键位还原按深度转义。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let mut inner_map = serde_json::Map::new();
    inner_map.insert(token.clone(), serde_json::json!("v"));
    let inner = serde_json::to_string(&serde_json::Value::Object(inner_map)).unwrap();
    let frame = serde_json::to_string(&serde_json::json!({ "b": inner })).unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert_eq!(spans.len(), 1, "键位出现点须有 span");
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("外层须合法");
    let inner_raw = outer["b"].as_str().expect("b 为字符串");
    let inner_parsed: serde_json::Value =
        serde_json::from_str(inner_raw).expect("键位还原后内层须可解析");
    assert_eq!(
        inner_parsed.get(secret).and_then(|v| v.as_str()),
        Some("v"),
        "键位凭据须按深度转义还原: {inner_raw}"
    );
}

#[tokio::test]
async fn restore_span_only_token_occurrence() {
    // 还原 span 逐出现点定位：同值独立明文不进入 span（不得子串全量查找）。
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let token = scope
        .pii_scope()
        .register("13800138000")
        .expect("PII 注册恒成功");
    let frame = format!(r#"{{"a":"{token}","b":"13800138000","c":"13800138000"}}"#);
    let (restored, spans) = scope.restore_response_with_spans(&vault, &frame);
    assert_eq!(
        spans.len(),
        1,
        "仅 token 出现点落在 span（不得子串全量查找整段 skip）: {spans:?}"
    );
    assert_eq!(&restored[spans[0].0..spans[0].1], "13800138000");
}

#[tokio::test]
async fn fragment_depth_unclosed_json_plus_one() {
    // 载体（`input_json_delta`）中未闭合 JSON 片段的 token 按 depth+1 计——
    // 片段拼接后 token 明文落入内层 JSON，转义须多一层；载体外 `delta.text` 不加一。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let frame = serde_json::to_string(&serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": { "type": "input_json_delta", "partial_json": format!("{{\"k\":\"{token}") }
    }))
    .unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert_eq!(spans.len(), 1, "token 出现点须有 span: {restored}");
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("外层须合法 JSON");
    let partial = outer["delta"]["partial_json"]
        .as_str()
        .expect("partial_json 为字符串");
    let inner: serde_json::Value = serde_json::from_str(&format!("{partial}\"}}"))
        .expect("片段拼接后内层须可解析（depth+1 转义）");
    assert_eq!(inner["k"], secret, "深层转义须严格互逆: {restored}");
    // 非载体：同形 text_delta 文本 SHALL NOT 加一（单层转义，片段拼接后内层非法）。
    let text_frame = serde_json::to_string(&serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": { "type": "text_delta", "text": format!("{{\"k\":\"{token}") }
    }))
    .unwrap();
    let (text_restored, text_spans) = scope.restore_response_with_spans_json(&vault, &text_frame);
    assert_eq!(text_spans.len(), 1);
    let text_outer: serde_json::Value =
        serde_json::from_str(&text_restored).expect("外层须合法 JSON");
    assert_eq!(
        text_outer["delta"]["text"].as_str().unwrap(),
        r#"{"k":"p@ss"q"#,
        "载体外字符串不得加一: {text_restored}"
    );
    // 完整可解析容器分支优先级不变：直接可解析且值与明文一致。
    let complete = serde_json::to_string(&serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {
            "type": "input_json_delta",
            "partial_json": serde_json::to_string(&serde_json::json!({ "k": token })).unwrap()
        }
    }))
    .unwrap();
    let (c_restored, _) = scope.restore_response_with_spans_json(&vault, &complete);
    let c_outer: serde_json::Value = serde_json::from_str(&c_restored).expect("外层须合法");
    let c_inner: serde_json::Value =
        serde_json::from_str(c_outer["delta"]["partial_json"].as_str().unwrap())
            .expect("完整容器须直接可解析");
    assert_eq!(c_inner["k"], secret, "完整容器分支不得回归: {c_restored}");
}

#[tokio::test]
async fn minted_set_records_only_produced_tokens() {
    // 白名单仅收本请求脱敏**实际产出**的 token；请求体自带的字面 token
    // 与他请求产出 token 均不入集，响应还原不得跨请求放行。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let produced = vault.register("produced-secret-001").unwrap();
    let literal = vault.register("literal-secret-002").unwrap();
    assert_ne!(produced, literal);
    let req = format!(r#"{{"a":"produced-secret-001","b":"{literal}"}}"#);
    let redacted = scope.redact_request(&vault, &detector, &req).await;
    assert!(
        redacted.contains(&produced),
        "真实明文须产出 token: {redacted}"
    );
    assert!(
        redacted.contains(&literal),
        "字面 token 须原样保护: {redacted}"
    );
    // 产出集合仅含 produced：literal 不还原、原样透传；全局映射不变。
    let restored = scope.restore_response(&vault, &format!("a={produced} b={literal}"));
    assert!(restored.contains("produced-secret-001"), "{restored}");
    assert!(
        restored.contains(&literal),
        "字面 token 须原样透传: {restored}"
    );
    assert!(!restored.contains("literal-secret-002"), "{restored}");
    assert_eq!(
        vault.restore_one(&literal).as_deref(),
        Some("literal-secret-002"),
        "进程单例映射不变，授权收紧在请求级"
    );
    // 他请求（独立 Scope）产出的 token 在本请求无授权。
    let other = Scope::new();
    mint_cred(&other, &vault, "literal-secret-002").await;
    let crossed = scope.restore_response(&vault, &literal);
    assert!(
        crossed.contains(&literal),
        "跨请求 token 须原样透传: {crossed}"
    );
    assert!(!crossed.contains("literal-secret-002"), "{crossed}");
}

#[tokio::test]
async fn restore_unauthorized_token_passthrough() {
    // 全局映射存在但非本请求产出的 token 不还原、原样透传（不删除）。
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let token = vault.register("leak-secret-001").unwrap();
    assert_eq!(
        vault.restore_one(&token).as_deref(),
        Some("leak-secret-001"),
        "全局映射须存在（泄漏链前提）"
    );
    let out = scope.restore_response(&vault, &format!("值 {token} 结束"));
    assert!(out.contains(&token), "未授权 token 须原样透传: {out}");
    assert!(!out.contains("leak-secret-001"), "不得还原明文: {out}");
    // 经本请求脱敏实际产出后方可还原。
    mint_cred(&scope, &vault, "leak-secret-001").await;
    let ok = scope.restore_response(&vault, &format!("值 {token} 结束"));
    assert_eq!(ok, "值 leak-secret-001 结束");
}

#[test]
fn scope_debug_redacts_conversation_context() {
    // FIX 2：`Scope` 手工 `Debug` 不得泄漏会话键 hex/租户指纹/密钥字节。
    let key = ConversationKey::for_test(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    let tenant = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let secret: Arc<[u8]> = Arc::from(vec![0x5Au8; 32].into_boxed_slice());
    let scope = Scope::new().with_conversation(
        key.clone(),
        tenant.to_string(),
        secret.clone(),
        Arc::new(PreviousResponseMap::new(4)),
    );
    let debug = format!("{scope:?}");
    assert!(!debug.contains(key.as_str()), "不得泄漏会话键 hex: {debug}");
    assert!(!debug.contains(tenant), "不得泄漏租户指纹: {debug}");
    assert!(
        !debug.contains(&format!("{secret:?}")),
        "不得泄漏密钥字节: {debug}"
    );
    assert!(debug.contains("[redacted]"), "须显式标注已脱敏: {debug}");
}

#[tokio::test]
async fn exit_passthrough_unregistered_complete_pii_token_four_boundaries() {
    // 四边界：① 未注册完整 token 原样透传；② 残缺维持剥离；
    // ③ 未注册新明文逐字节透传；④ 已注册 token 照常还原。
    let vault = CredentialVault::new();

    let scope = Scope::new();
    let (out, spans) = scope.restore_response_with_spans(&vault, "邮箱是__PII_2_3bd028ca__。");
    assert_eq!(
        out, "邮箱是__PII_2_3bd028ca__。",
        "未注册完整 token 须原样透传: {out:?}"
    );
    assert!(spans.is_empty());

    let scope2 = Scope::new();
    for partial in ["__PI", "__PII_1_ab", "__PII_1_ab12cd34"] {
        let (out, _) = scope2.restore_response_with_spans(&vault, &format!("x {partial} y"));
        assert!(!out.contains("__PI"), "残缺须剥离: {partial} -> {out:?}");
    }

    let scope3 = Scope::new();
    let (out3, _) = scope3.restore_response_with_spans(&vault, "另一个号码是13900000000");
    assert_eq!(out3, "另一个号码是13900000000", "新明文透传不受影响");

    let shared = Arc::new(PiiScope::new());
    let token = shared.register("13812345678").expect("注册恒成功");
    let scope4 = Scope::with_shared_pii(shared, false);
    let (out4, spans4) = scope4.restore_response_with_spans(&vault, &format!("回拨 {token} 结束"));
    assert_eq!(
        out4, "回拨 13812345678 结束",
        "已注册 token 照常还原: {out4}"
    );
    assert_eq!(spans4.len(), 1);
}

#[test]
fn release_frame_payload_restore_and_identity_branch() {
    // fix 3 判据：释放残余载荷含完整 token 时经 `_json` 还原为明文且 JSON 合法；
    // 部分前缀（carry 唯一产出）不得被判为完整 token——pump 侧据此走恒等回吐。
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let frame = serde_json::json!({
        "type": "response.output_text.delta",
        "item_id": "msg_0",
        "output_index": 0,
        "content_index": 0,
        "delta": token,
    })
    .to_string();
    assert!(
        !scan_token_forms(&frame).is_empty(),
        "完整 token 载荷须被判为可还原"
    );
    let (restored, _) = scope.restore_response_with_spans_json(&vault, &frame);
    let v: serde_json::Value = serde_json::from_str(&restored).expect("还原后须合法 JSON");
    assert_eq!(
        v["delta"], "13812345678",
        "释放载荷完整 token 须还原: {restored}"
    );

    let partial = serde_json::json!({
        "type": "response.output_text.delta",
        "delta": "__PI",
    })
    .to_string();
    assert!(
        scan_token_forms(&partial).is_empty(),
        "部分前缀不得被判为完整 token（走恒等回吐）"
    );
}
