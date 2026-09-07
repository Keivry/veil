use {
    crate::error::{Result, VeilError},
    std::sync::atomic::{AtomicBool, Ordering},
};

pub trait KeePassBackend: Send + Sync + std::fmt::Debug {
    fn is_unlocked(&self) -> bool;
    fn fetch_credential(&self, caller: &str) -> Result<String>;
}

#[derive(Debug, Default)]
pub struct MockKeePass {
    unlocked: AtomicBool,
}

impl MockKeePass {
    pub fn locked() -> Self {
        Self {
            unlocked: AtomicBool::new(false),
        }
    }

    pub fn unlocked() -> Self {
        Self {
            unlocked: AtomicBool::new(true),
        }
    }

    pub fn set_unlocked(&self, value: bool) { self.unlocked.store(value, Ordering::SeqCst); }
}

impl KeePassBackend for MockKeePass {
    fn is_unlocked(&self) -> bool { self.unlocked.load(Ordering::SeqCst) }

    fn fetch_credential(&self, caller: &str) -> Result<String> {
        if !self.is_unlocked() {
            return Err(VeilError::Unavailable {
                message: "KeePass 未解锁".to_string(),
            });
        }
        Ok(format!("__MOCK_CRED_{caller}__"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 未解锁返回503() {
        let backend = MockKeePass::locked();
        let err = backend.fetch_credential("c1").unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn 解锁后下发占位载荷() {
        let backend = MockKeePass::unlocked();
        assert!(backend.fetch_credential("c1").is_ok());
    }
}
