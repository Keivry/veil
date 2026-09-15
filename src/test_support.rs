//! 共享测试支撑（`DCD-8`）。
//!
//! 文件 800 行红线断言单一实现：各测试模块以 `include_str!` 提供目标源码，
//! 本模块只承载检查逻辑，消除 18 份逐字复制（`veil-arch-file-size-closeout` /
//! `hygiene-round4`）。

/// 断言 `src`（`include_str!` 读入的源码）总行数 ≤ 800；超限 panic 并提示拆分。
pub(crate) fn file_len_under_800_or_split(name: &str, src: &str) {
    let lines = src.lines().count();
    assert!(
        lines <= 800,
        "{name} {lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
}
