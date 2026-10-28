//! 文件层生产文件行数红线（`file_layer` 拆分后逐文件自检）。

#[test]
fn file_layer_production_files_under_redline() {
    crate::test_support::file_len_under_800_or_split(
        "file_layer/mod.rs",
        include_str!("../mod.rs"),
    );
    crate::test_support::file_len_under_800_or_split(
        "file_layer/storage.rs",
        include_str!("../storage.rs"),
    );
}
