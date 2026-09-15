use {
    super::super::submit_pending_with_branch,
    crate::service::{
        credential::test_support::{cred_env, cred_state_with_sink},
        matrix::{MatrixBranch, NotificationSink},
    },
    std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
    },
};

/// `CRD-5` 测试 sink：统计预置 reaction 次数，可模拟 reaction 发送失败。
#[derive(Debug)]
struct ReactionSink {
    next: AtomicU64,
    reactions: AtomicUsize,
    fail_reactions: bool,
}

impl ReactionSink {
    fn new(fail_reactions: bool) -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(1),
            reactions: AtomicUsize::new(0),
            fail_reactions,
        })
    }

    fn reactions(&self) -> usize { self.reactions.load(Ordering::SeqCst) }
}

impl NotificationSink for ReactionSink {
    fn send_text(&self, _text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn send_text_tracked(
        &self,
        _text: String,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let id = format!("$preseed-{}", self.next.fetch_add(1, Ordering::SeqCst));
        Box::pin(async move { Some(id) })
    }

    fn send_reaction<'a>(
        &'a self,
        _event_id: &'a str,
        _key: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let ok = !self.fail_reactions;
        if ok {
            self.reactions.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(async move { ok })
    }
}

#[tokio::test]
async fn approval_reaction_preseed() {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let sink = ReactionSink::new(false);
    let state = cred_state_with_sink(&env, sink.clone());
    submit_pending_with_branch(
        &state,
        "/s/pre-reg.sh",
        "register审批",
        MatrixBranch::Register,
        "",
        None,
    )
    .await
    .unwrap();
    assert_eq!(sink.reactions(), 3, "注册分支须预置 🔓/✅/❎");
    submit_pending_with_branch(
        &state,
        "/s/pre-cred.sh",
        "hash_mismatch",
        MatrixBranch::Credential,
        "网易",
        None,
    )
    .await
    .unwrap();
    assert_eq!(sink.reactions(), 5, "凭据分支须预置 ✅/❎");
    submit_pending_with_branch(
        &state,
        "/s/pre-hash.sh",
        "hash-change",
        MatrixBranch::HashChange,
        "",
        None,
    )
    .await
    .unwrap();
    assert_eq!(sink.reactions(), 8, "哈希变更分支须预置 🔓/✅/❎");
}

#[tokio::test]
async fn reaction_preseed_failure_warns() {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let sink = ReactionSink::new(true);
    let state = cred_state_with_sink(&env, sink.clone());
    let id = submit_pending_with_branch(
        &state,
        "/s/pre-fail.sh",
        "register审批",
        MatrixBranch::Register,
        "",
        None,
    )
    .await
    .expect("预置 reaction 失败不得阻断建单");
    assert!(id.starts_with("$preseed-"), "建单须成功: {id}");
    assert_eq!(state.pending.len(), 1, "建单仍成立");
    assert_eq!(sink.reactions(), 0, "失败不得计为成功");
}
