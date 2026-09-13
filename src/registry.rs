//! 调用方注册表门面（B6/D6）：按职责拆为 `entry`（条目/参数/宽限）、
//! `acl`（授权判定）、`store`（加载/原子落盘/完整性/绑定哈希）、
//! `migrate`（Python 旧格式迁移）；公开路径 `crate::registry::*` 经 re-export 兼容。

mod acl;
mod entry;
mod migrate;
mod store;

#[cfg(test)]
pub(crate) use store::{
    BIND_READ_DELAY_MS,
    BIND_READ_ENTERED,
    SAVE_TEST_DELAY_MS,
    SAVE_TEST_WRITE_STARTS,
};
pub use {
    acl::AuthorizationDecision,
    entry::{CallerEntry, HashChangeOutcome, OLD_HASH_GRACE_SECS, RegisterParams},
    store::{
        BIND_SCRIPT_MAX_BYTES,
        CallerRegistry,
        bind_script_sha256,
        bind_script_sha256_async,
        script_sha256_of_bytes,
        write_atomic,
    },
};

#[cfg(test)]
mod tests {
    #[test]
    fn file_len_under_800_or_split() {
        // H2.1 红线看护（口径=文件总行，含测试与注释）：超 800 即失败，
        // 须按 H1 门面+子模块模板拆分，不得只改数字放行。
        const SELF_SRC: &str = include_str!("registry.rs");
        let lines = SELF_SRC.lines().count();
        assert!(
            lines <= 800,
            "registry.rs {lines} 行超 800 红线：须拆分（见 veil-review-followup-arch-hygiene H1/H2.1）"
        );
    }
}
