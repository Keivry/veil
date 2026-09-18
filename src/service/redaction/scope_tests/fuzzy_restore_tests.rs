//! fuzzy 还原开关精确/序号回查单测（自 `scope_tests.rs` 拆出，测试名与断言不变）。

use super::super::*;

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
