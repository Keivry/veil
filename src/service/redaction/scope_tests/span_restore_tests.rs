//! span 还原与逐 token 一致性单测（自 `scope_tests.rs` 拆出，测试名与断言不变）。

use {
    super::{super::*, mint_cred},
    crate::service::pii::apply_spans,
};

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
    // B2/D2：主还原与 span 回查均逐 token 直查，全量快照计数零增量。
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
    let pii_tok = scope.pii_scope().register("13812345678", false).unwrap();
    let sample = format!(
        "{{\"x\":\"{a}{b}\",\"y\":\"__VG_CRED_999999__\",\"z\":\"{pii_tok}\",\"e\":\"换行\\n引号\\\"\"}}"
    );
    let per_token = scope.restore_response(&vault, &sample);
    let full = {
        let step1 = vault.restore(&sample);
        let step2 = scope.pii_scope().restore(&step1);
        let step3 = vault.strip_hallucinated(&step2, None);
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
