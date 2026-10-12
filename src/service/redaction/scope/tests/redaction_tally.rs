//! 请求侧三项脱敏计数与值级采样单测（自 `scope/tests.rs` 外迁，
//! 避免单文件越 800 行红线）。

use {
    super::super::*,
    crate::service::metrics::{PiiSamplerConfig, PiiValueSampler, SampleBinding},
    std::sync::Arc,
};

fn make_sampler(enabled: bool) -> Arc<PiiValueSampler> {
    let dir = std::env::temp_dir().join(format!("veil-scope-sample-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    Arc::new(PiiValueSampler::new(
        PiiSamplerConfig {
            enabled,
            persist: false,
            hmac_key: None,
        },
        dir.join(format!("m-{enabled}.sqlite")),
    ))
}

#[tokio::test]
async fn request_counts_miss_then_hit_within_single_leaf() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let text = "号码 13812345678 再来 13812345678 结束";
    let (out, _res, tally) = scope
        .redact_request_with_report_and_counts(&vault, &detector, text)
        .await;
    assert!(out.contains("__PII_"), "{out}");
    assert_eq!(tally.pii_miss, 1, "首次出现须计新铸");
    assert_eq!(tally.pii_hits, 1, "二次出现须计复用");
    assert_eq!(tally.cred_hits, 0);
}

#[tokio::test]
async fn credential_replacements_counted_per_occurrence() {
    let vault = CredentialVault::new();
    vault.register("cred-secret-001").unwrap();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let text = "a cred-secret-001 b cred-secret-001";
    let (out, _res, tally) = scope
        .redact_request_with_report_and_counts(&vault, &detector, text)
        .await;
    assert!(!out.contains("cred-secret-001"), "{out}");
    assert_eq!(tally.cred_hits, 2, "两处凭据明文须计两次替换");
    assert_eq!((tally.pii_hits, tally.pii_miss), (0, 0));
}

#[tokio::test]
async fn custom_rule_values_excluded_from_counts() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    detector.load_custom_all(&[("acct".to_string(), r"ACCT-[0-9]{4}".to_string())], &[]);
    let scope = Scope::new();
    let (out, _res, tally) = scope
        .redact_request_with_report_and_counts(&vault, &detector, "账号 ACCT-1234 结束")
        .await;
    assert!(out.contains("__PII_"), "自定义命中须替换: {out}");
    assert_eq!(
        (tally.pii_hits, tally.pii_miss, tally.cred_hits),
        (0, 0, 0),
        "自定义规则命中须显式排除三项计数"
    );
}

#[tokio::test]
async fn sampler_invoked_on_request_path_when_enabled() {
    let sampler = make_sampler(true);
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    scope.configure_sampling(SampleBinding {
        sampler: Some(sampler.clone()),
        is_chat_tail: true,
        upstream: "8877".to_string(),
    });
    let _ = scope
        .redact_request_with_report_and_counts(&vault, &detector, "号码 13812345678")
        .await;
    let top = sampler.top_n(5);
    assert_eq!(top.len(), 1, "启用采样时请求侧须产生条目");
    assert_eq!(top[0].upstream, "8877", "upstream 须为入口端口字符串");
    assert_eq!(top[0].kind, "phone");
}

#[tokio::test]
async fn sampler_disabled_and_non_chat_produce_no_entries() {
    let sampler = make_sampler(false);
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    scope.configure_sampling(SampleBinding {
        sampler: Some(sampler.clone()),
        is_chat_tail: true,
        upstream: "8877".to_string(),
    });
    let _ = scope
        .redact_request_with_report_and_counts(&vault, &detector, "号码 13812345678")
        .await;
    assert!(sampler.top_n(5).is_empty(), "关闭态不得产生采样条目");
    assert_eq!(sampler.stats().1, 1, "关闭态须计 skipped_disabled");

    let sampler2 = make_sampler(true);
    let scope2 = Scope::new();
    scope2.configure_sampling(SampleBinding {
        sampler: Some(sampler2.clone()),
        is_chat_tail: false,
        upstream: "8877".to_string(),
    });
    let _ = scope2
        .redact_request_with_report_and_counts(&vault, &detector, "号码 13800138000")
        .await;
    assert!(
        sampler2.top_n(5).is_empty(),
        "非 chat-tail 不得产生采样条目"
    );
    assert_eq!(sampler2.stats().2, 1, "非 chat-tail 须计 skipped_non_chat");
}

#[tokio::test]
async fn sampler_absent_leaves_counts_intact() {
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let (_out, _res, tally) = scope
        .redact_request_with_report_and_counts(&vault, &detector, "号码 13812345678")
        .await;
    assert_eq!(
        (tally.pii_miss, tally.pii_hits),
        (1, 0),
        "未接线采样不影响计数"
    );
}
