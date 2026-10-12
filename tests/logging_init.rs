//! 全局订阅者安装幂等（独立 integration 二进制：`set_global_default` 只在本进程
//! 生效，不污染 lib 测试进程与 `test_support.rs` 的线程局部捕获）。
//!
//! 本文件只允许一个测试：多个测试并发争抢全局安装点时，`init()` 的返回值次序
//! 不确定。

#[test]
fn init_is_idempotent_and_never_panics() {
    assert!(veil::logging::init(), "首次安装应成功");
    assert!(
        !veil::logging::init(),
        "重复安装应返回 false（try_init 语义），且不 panic、不中止进程"
    );
}
