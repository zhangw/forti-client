use std::sync::Arc;
use tokio::sync::watch;

/// Cloneable, level-triggered shutdown signal.
///
/// Unlike calling `tokio::signal::ctrl_c()` at individual wait sites, this
/// remembers cancellation, so a Ctrl+C received between state transitions
/// cannot be lost.
#[derive(Clone, Debug)]
pub struct Shutdown {
    sender: Arc<watch::Sender<bool>>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    pub fn new() -> Self {
        let (sender, _receiver) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn cancel(&self) {
        // `send` discards the value when there are no receivers. `send_replace`
        // always stores it, which is essential for cancellation between states.
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }

        let mut receiver = self.sender.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancellation_is_remembered_for_late_waiters() {
        let shutdown = Shutdown::new();
        shutdown.cancel();
        tokio::time::timeout(Duration::from_millis(50), shutdown.cancelled())
            .await
            .expect("late waiter must observe cancellation");
    }

    #[tokio::test]
    async fn clone_observes_cancellation() {
        let shutdown = Shutdown::new();
        let waiter = shutdown.clone();
        let task = tokio::spawn(async move { waiter.cancelled().await });
        shutdown.cancel();
        tokio::time::timeout(Duration::from_millis(50), task)
            .await
            .expect("clone must wake")
            .expect("waiter task must succeed");
    }
}
