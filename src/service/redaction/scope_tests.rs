//! `Scope` 请求/响应编排单测（自 `scope.rs` 拆出；测试名与断言不变）。

use {
    super::*,
    crate::service::{credential_vault::redact_with_map, pii::apply_spans},
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
    assert!(redacted.contains("__VG_CRED_"), "{redacted}");
    assert!(redacted.contains("__PII_"), "{redacted}");
    // JSON 语义等价：仍可解析，键名层级不变。
    let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
    assert!(v.get("pwd").is_some() && v.get("phone").is_some());
    let restored = scope.restore_response(&vault, &redacted);
    assert!(restored.contains("my-secret-001"), "{restored}");
    assert!(restored.contains("13812345678"), "{restored}");
}

#[tokio::test]
async fn response_new_pii_not_restored() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    // 请求期未注册的新 PII：响应侧以新占位符呈现。
    let resp = scope
        .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
        .await;
    assert!(!resp.contains("8.8.8.8"), "{resp}");
    assert!(resp.contains("__PII_"), "{resp}");
    // 请求还原表不含该 token：restore 原样保留。
    let again = scope.restore_response(&vault, &resp);
    assert!(again.contains("__PII_"), "{again}");
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
    // B 持有 A 的占位符：还原失败并原样保留。
    let restored_by_b = b.restore_response(&vault, &redacted);
    assert!(restored_by_b.contains("__PII_"), "{restored_by_b}");
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
    let dirty = "正文 __VG_CRED_000 与 __PII_2_ab 结尾";
    let cleaned = scope.redact_request_plain(&vault, &detector, dirty).await;
    assert!(!cleaned.contains("__VG_CRED_000"), "{cleaned}");
    assert!(!cleaned.contains("__PII_2_ab"), "{cleaned}");
    let restored = scope.restore_response(&vault, "ok __VG_CRED_12");
    assert!(!restored.contains("__VG_CRED_12"), "{restored}");
}

#[tokio::test]
async fn skip_segments_recursive_stringified_pii() {
    // T8/D8：同一响应既还原凭据（跳过区间）又命工具参数内嵌套 stringified JSON 新 PII。
    let vault = CredentialVault::new();
    vault.register("veil-secret-001").unwrap();
    let detector = PiiDetector::new();
    detector.load_dict(&[("a\"b".to_string(), "hostname".to_string())]);
    let scope = Scope::new();
    let frame = r#"{"a":"__VG_CRED_000001__","b":"{\"host\":\"a\\\"b\"}"}"#;
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, frame);
    assert!(restored.contains("veil-secret-001"), "{restored}");
    assert!(!spans.is_empty());
    let out = scope
        .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
        .await;
    assert!(out.contains("veil-secret-001"), "凭据明文须保留: {out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("输出须合法 JSON");
    let inner: serde_json::Value =
        serde_json::from_str(v["b"].as_str().expect("b 为字符串")).expect("嵌套 JSON 须完好");
    assert!(
        inner["host"]
            .as_str()
            .is_some_and(|s| s.starts_with("__PII_")),
        "嵌套 dict PII 须被掩码: {out}"
    );
}

#[tokio::test]
async fn skip_segments_byte_identical() {
    // T8：仅跳过区间且零命中时输出与输入逐字节一致。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    for (text, skip) in [
        (r#"{"k":"secret-abc"}"#, (6usize, 16usize)),
        (r#"{"b":2,"a":1}"#, (2, 3)),
    ] {
        let out = scope
            .redact_response_new_pii_with_skip(&vault, &detector, text, &[skip])
            .await;
        assert_eq!(out, text, "零命中跳过须字节一致: {text}");
    }
}

#[tokio::test]
async fn skip_span_boundaries() {
    // T8/9.2：相邻/重叠 span、段首尾截断、关闭响应侧检测旁路。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let text = r#"{"k":"AAAABBBB"}"#;
    assert_eq!(
        scope
            .redact_response_new_pii_with_skip(&vault, &detector, text, &[(0, 1)])
            .await,
        text,
        "段首截断须字节一致"
    );
    assert_eq!(
        scope
            .redact_response_new_pii_with_skip(
                &vault,
                &detector,
                text,
                &[(text.len() - 1, text.len())]
            )
            .await,
        text,
        "段尾截断须字节一致"
    );
    assert_eq!(
        scope
            .redact_response_new_pii_with_skip(&vault, &detector, text, &[(5, 9), (9, 13)])
            .await,
        text,
        "相邻 span 须字节一致"
    );
    assert_eq!(
        scope
            .redact_response_new_pii_with_skip(&vault, &detector, text, &[(5, 10), (7, 12)])
            .await,
        text,
        "重叠 span 须字节一致"
    );
    // 关闭响应侧检测：旁路直接透传，跳过区间与新 PII 均不改写。
    let off = Scope::with_opts(false, false);
    let pii_text = r#"{"k":"secret-abc","p":"8.8.8.8"}"#;
    let out = off
        .redact_response_new_pii_with_skip(&vault, &detector, pii_text, &[(6, 16)])
        .await;
    assert_eq!(out, pii_text, "关闭响应侧检测须整段透传");
}

#[tokio::test]
async fn response_side_disabled_passes_through() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::with_opts(false, false);
    let resp = scope
        .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
        .await;
    assert!(resp.contains("8.8.8.8"), "{resp}");
    assert!(!resp.contains("__PII_"), "{resp}");
    let open = Scope::with_opts(true, false);
    let masked = open
        .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
        .await;
    assert!(!masked.contains("8.8.8.8"), "{masked}");
}

#[tokio::test]
async fn response_zero_replacement_byte_identical() {
    // H1/D2：零替换响应帧逐字节透传（不触发 loads→walk→dumps 重排：
    // 键序保持 b,a，无空白/数字改写）。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let frame = r#"{"b":2,"a":1}"#;
    let out = scope
        .redact_response_new_pii(&vault, &detector, frame)
        .await;
    assert_eq!(out, frame, "零替换须逐字节透传");
    let out2 = scope
        .redact_response_new_pii_with_skip(&vault, &detector, frame, &[(0, 1)])
        .await;
    assert_eq!(out2, frame, "skip 入口零替换同样逐字节透传");
}

#[tokio::test]
async fn json_key_order_preserved() {
    // H1/D2：必须重序列化时对象键序保持原始顺序（`preserve_order`），
    // 仅命中叶被替换为 `__PII_...__`（非字典序 a,b）。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let out = scope
        .redact_response_new_pii(&vault, &detector, r#"{"b":"8.8.8.8","a":1}"#)
        .await;
    assert!(out.contains("__PII_"), "{out}");
    let key_b = out.find("\"b\"").expect("b 键须在");
    let key_a = out.find("\"a\"").expect("a 键须在");
    assert!(key_b < key_a, "键序须保持 b,a: {out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("重序列化输出须合法");
    assert_eq!(v["a"], 1);
    assert!(
        v["b"].as_str().is_some_and(|s| s.starts_with("__PII_")),
        "{out}"
    );
}

#[tokio::test]
async fn response_number_literal_passthrough() {
    // H1/D2：零替换路径数字表示/空白逐字节保留（`1e3` 不得改写 `1000.0`）。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    for frame in [r#"{"n":1e3}"#, r#"{ "a" : 1 , "b" : 2 }"#] {
        let out = scope
            .redact_response_new_pii(&vault, &detector, frame)
            .await;
        assert_eq!(out, frame, "零替换须逐字节保留数字/空白");
    }
}

#[tokio::test]
async fn three_wrappers_nasty_scope_paths() {
    // G1.2 对照 Python `tests/vault_stable_test.py:298-342`：含引号密码、
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

    // ① token 脱敏：凭据值替换为 `__VG_CRED_` token。
    let redacted = scope.redact_request(&vault, &detector, &raw).await;
    let rv: serde_json::Value = serde_json::from_str(&redacted).expect("脱敏输出须合法 JSON");
    assert!(
        rv["pwd"]
            .as_str()
            .is_some_and(|s| s.starts_with("__VG_CRED_")),
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
    // G1.1 对照 Python `tests/vault_stable_test.py:132-167`：
    // `PII_FUZZY_RESTORE` 关闭时大小写漂移不还原（精确原样保留），
    // 开启时按序号回查还原。`__PII_<seq>_ZZZZABCD__` 为大写非 hex 漂移形。
    let vault = CredentialVault::new();
    let plain = "13812345678";
    let exact = Scope::with_opts(true, false);
    let token = exact
        .pii_scope()
        .register(plain, false)
        .expect("注册恒成功");
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
    let fuzzy = Scope::with_opts(true, true);
    let token2 = fuzzy
        .pii_scope()
        .register(plain, false)
        .expect("注册恒成功");
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
    let exact = Scope::with_opts(true, false);
    let token = exact.pii_scope().register(plain, false).unwrap();
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
    let scope2 = Scope::with_opts(true, true);
    let token2 = scope2.pii_scope().register(plain, false).unwrap();
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
    // D7：合法正文前缀续段/单词字符逐字节不变（不得误删）。
    for legal in [
        "__VG_CREDENTIALS",
        "__VG_CUSTOMER",
        "__VG_CREDIT",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文不得误删: {legal}");
    }
    // 真残缺仍被清理（保护不退化）。
    for partial in ["__VG_", "__VG_CRED_000", "__PII_3_ab"] {
        let cleaned = strip_partials(partial);
        assert!(!cleaned.contains("__VG"), "{partial} -> {cleaned:?}");
        assert!(!cleaned.contains("__PI"), "{partial} -> {cleaned:?}");
    }
}

#[test]
fn strip_partials_differential() {
    // design D7 差分用例表（合法正文 vs 真残缺 vs 前缀本身），逐条锁定边界。
    for legal in [
        "__VG_CREDENTIALS",
        "__VG_CUSTOMER",
        "__VG_CREDIT",
        "__VG_CREDX",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
        "__VG_CRED_000extra",
        "__PII_3_abzz",
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文须不变: {legal}");
    }
    for partial in [
        "__VG_",
        "__VG__",
        "__VG_C",
        "__VG_CR",
        "__VG_CRE",
        "__VG_CRED",
        "__VG_CRED_",
        "__VG_CRED_000",
        "__VG_CRED_000001",
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
    // 完整形态口径：凭据完整剥离（还原先行）；PII 完整保留（响应期新 token）。
    assert_eq!(strip_partials("__VG_CRED_000001__"), "");
    assert!(
        strip_partials("__PII_1_ab12cd34__").contains("__PII_1_ab12cd34__"),
        "PII 完整形态须保留"
    );
    // 尾随边界（空白）剥离，后随合法单词字符不剥离。
    assert_eq!(strip_partials("尾部 __VG_CRED_12 结束"), "尾部  结束");
    assert_eq!(
        strip_partials("正文 __PII_2_ab 结束"),
        "正文  结束",
        "残缺后随空白须剥离"
    );
}

#[test]
fn strip_partial_and_token_fn_semantics() {
    let vault = CredentialVault::new();
    assert_eq!(strip_partials("a __VG_CRED_00 b"), "a  b");
    assert_eq!(strip_partials("a __PII_3_ab b"), "a  b");
    assert_eq!(strip_token_forms(&vault, "x __VG_CRED_123456__ y"), "x  y");
    // PII 完整形态保留（响应期新 token 语义）。
    assert!(strip_token_forms(&vault, "x __PII_1_ab12cd34__ y").contains("__PII_1_ab12cd34__"));
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
async fn restore_spans_skip_prevents_remask() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let redacted = scope
        .redact_request(&vault, &detector, r#"{"phone":"13812345678"}"#)
        .await;
    assert!(redacted.contains("__PII_"), "{redacted}");
    let (restored, spans) = scope.restore_response_with_spans(&vault, &redacted);
    assert!(restored.contains("13812345678"), "{restored}");
    assert!(!spans.is_empty());
    assert!(
        spans
            .iter()
            .any(|(s, e)| &restored[*s..*e] == "13812345678"),
        "{spans:?}"
    );
    // 带 skip：还原明文保持明文。
    let kept = scope
        .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
        .await;
    assert!(kept.contains("13812345678"), "{kept}");
    // 对照（不带 skip）：同一明文被套上响应 token，证明 skip 生效。
    let masked = scope
        .redact_response_new_pii(&vault, &detector, &restored)
        .await;
    assert!(!masked.contains("13812345678"), "{masked}");
    assert!(masked.contains("__PII_"), "{masked}");
}

#[test]
fn credential_restore_spans_cover_plaintext() {
    let vault = CredentialVault::new();
    vault.register("my-secret-001").expect("注册恒成功");
    let scope = Scope::new();
    let masked = redact_with_map("密码 my-secret-001 结束", &vault.snapshot_p2t());
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

#[test]
fn per_token_lookup_does_not_snapshot_full_vault() {
    let vault = CredentialVault::new();
    let secret = "complexity-secret-001";
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();
    let text = format!("{token} {token} {token}");
    let before = vault.snapshot_calls();
    let (restored, spans) = scope.restore_response_with_spans(&vault, &text);
    assert_eq!(restored, format!("{secret} {secret} {secret}"));
    assert_eq!(spans.len(), 3);
    // B2/D2：主还原与 span 回查均逐 token 直查，全量快照计数零增量。
    assert_eq!(
        vault.snapshot_calls() - before,
        0,
        "逐 token 直查不得触发全表克隆（含主还原路径）"
    );
}

#[test]
fn restore_per_token_parity() {
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let a = vault.register("parity-secret-alpha").unwrap();
    let b = vault.register("parity-secret-beta").unwrap();
    let pii_tok = scope.pii_scope().register("13812345678", false).unwrap();
    let sample = format!(
        "{{\"x\":\"{a}{b}\",\"y\":\"__VG_CRED_999999__\",\"z\":\"{pii_tok}\",\"e\":\"换行\\n引号\\\"\"}}"
    );
    let per_token = scope.restore_response(&vault, &sample);
    let full = {
        let step1 = vault.restore(&sample);
        let step2 = scope.pii_scope().restore(&step1);
        let step3 = vault.strip_hallucinated(&step2);
        strip_partials(&step3)
    };
    assert_eq!(per_token, full, "逐 token 还原须与全量路径逐字节一致");
    assert!(per_token.contains("parity-secret-alpha"), "{per_token}");
    assert!(per_token.contains("parity-secret-beta"), "{per_token}");
    assert!(!per_token.contains("__VG_CRED_999999__"), "{per_token}");
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
fn restore_idempotent_unknown_passthrough() {
    let vault = vault_with_secret("my-secret-001");
    let scope = Scope::new();
    let tok = scope.pii_scope().register("13812345678", false).unwrap();
    let mixed = format!("回拨 {tok} 与 __PII_9_ab12cd34__ 及 my-secret-001");
    let once = scope.restore_response(&vault, &mixed);
    assert!(once.contains("13812345678"), "{once}");
    assert!(once.contains("__PII_9_ab12cd34__"), "{once}");
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
    assert!(scope_a.restore_response(&vault, &out_b).contains("__PII_"));
    assert!(scope_b.restore_response(&vault, &out_a).contains("__PII_"));
    assert!(
        scope_a
            .restore_response(&vault, &out_a)
            .contains("13800138000")
    );
}

#[test]
fn nested_stringified_json_restore_inner_valid() {
    // RED-1：两层嵌套 stringified JSON 参数内含带引号凭据明文，还原写回须按
    // 实际 JSON 深度转义，内层结构保持有效、无非法裸 `"`。
    let vault = CredentialVault::new();
    let secret = "p@ss\"q";
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();
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

#[test]
fn restore_json_aware_regression() {
    // RED-1 回归：单层帧仅命中 span 单层转义、其余字节等价；零替换帧不触发
    // `loads→dumps` 重排（逐字节透传）。
    let vault = CredentialVault::new();
    let secret = "p@ss\"q";
    let token = vault.register(secret).unwrap();
    let scope = Scope::new();
    let single = format!("{{\"msg\":\"hi {token}\"}}");
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &single);
    assert_eq!(restored, "{\"msg\":\"hi p@ss\\\"q\"}");
    assert_eq!(spans.len(), 1);
    let zero = r#"{"b":2,"a":1e3}"#;
    let (out, zero_spans) = scope.restore_response_with_spans_json(&vault, zero);
    assert_eq!(out, zero, "零替换须逐字节透传");
    assert!(zero_spans.is_empty());
}
