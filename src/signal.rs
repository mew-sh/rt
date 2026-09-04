/// Platform-specific signal handling.
///
/// On Unix-like systems (Linux, macOS, FreeBSD), this handles SIGUSR1
/// to dump diagnostic information (e.g., KCP SNMP statistics).
///
/// On Windows, signal handling for SIGUSR1 is not available; this module
/// provides a no-op implementation.
use tracing::info;

/// Start the platform-specific signal handler.
///
/// On Unix: listens for SIGUSR1 and logs diagnostic info.
/// On Windows: no-op.
pub async fn signal_handler() {
    platform_signal_handler().await;
}

#[cfg(unix)]
async fn platform_signal_handler() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[signal] failed to register SIGUSR1 handler: {}", e);
            return;
        }
    };

    info!("[signal] SIGUSR1 handler registered");

    loop {
        sigusr1.recv().await;
        info!("[signal] SIGUSR1 received -- dumping diagnostics");
        // In a full implementation, this would dump KCP SNMP statistics
        // or other runtime diagnostics.
        dump_diagnostics();
    }
}

#[cfg(windows)]
async fn platform_signal_handler() {
    // Windows does not support Unix signals.
    // This function returns immediately (no-op).
}

/// Dump runtime diagnostics.  Called when SIGUSR1 is received on Unix.
fn dump_diagnostics() {
    info!("[diagnostics] rt is running");
    // Future: dump KCP SNMP stats, connection counts, chain state, etc.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_diagnostics_does_not_panic() {
        dump_diagnostics();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_signal_handler_can_be_spawned() {
        // Just verify it can be spawned without panic.
        // We do not send an actual signal in the test.
        let handle = tokio::spawn(async {
            tokio::select! {
                _ = signal_handler() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
            }
        });
        handle.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_signal_handler_noop_on_windows() {
        // On Windows, signal_handler() should return immediately.
        signal_handler().await;
    }
}
