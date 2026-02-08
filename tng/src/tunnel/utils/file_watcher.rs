use anyhow::Context;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing;

use notify::{
    event::{AccessKind, CreateKind, ModifyKind},
    recommended_watcher, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _,
};

/// A simple file change notifier. Only emits when the target file is meaningfully modified.
///
/// Does not send a "stopped" event — channel close implies termination.
pub struct FileWatcher {
    path: PathBuf,
    _watcher: RecommendedWatcher,
    rx: mpsc::UnboundedReceiver<Result<(), anyhow::Error>>,
}

impl FileWatcher {
    /// Start watching a file.
    ///
    /// Returns a receiver that yields:
    /// - `Ok(())` when the file changed and should be reloaded,
    /// - `Err(error)` when an internal watcher error occurs (logging still happens here),
    ///
    /// When the stream ends (recv() returns None), the watcher has stopped.
    pub fn new(path: PathBuf) -> Result<FileWatcher, anyhow::Error> {
        let (tx, rx) = mpsc::unbounded_channel();

        tracing::info!(?path, "Starting file watcher");

        let mut watcher: RecommendedWatcher = recommended_watcher({
            let path = path.clone();

            // We use a mutable local variable to track whether the file was modified
            // since the last close. This helps us avoid reloading on temporary/incomplete writes.
            let mut modified = false;

            move |res: Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        // Check if this event is related to our target file
                        if event.paths.iter().any(|p| p == &path) {
                            let should_send = {
                                match event.kind {
                            // File was renamed (e.g., atomic replace via `mv`) — treat as immediate reload
                            EventKind::Modify(ModifyKind::Name(_)) => true,

                            // Data content changed (e.g., `echo > file`, editor save)
                            // Mark that a modification occurred, but don't trigger reload yet.
                            // We wait for the file to be closed to ensure write completeness.
                            EventKind::Modify(ModifyKind::Data(_)) |
                            // New file created (e.g., `touch`, or recreated after deletion)
                            EventKind::Create(CreateKind::File) => {
                                modified = true;
                                false // Defer reload until close
                            }

                            // Close event: the writing process has finished and released the file.
                            // This is the safest moment to reload, as the file should now be complete.
                            EventKind::Access(AccessKind::Close(_)) => {
                                if modified {
                                    modified = false; // Reset flag to avoid duplicate triggers
                                    true // Trigger reload now
                                } else {
                                    false // No prior data change, ignore
                                }
                            }

                            // Ignore all other event kinds (e.g., read close, metadata change, etc.)
                            _ => false,
                        }
                            };

                            if should_send {
                                let _ = tx.send(Ok(())); // Request reload
                            }
                        }
                    }
                    Err(error) => {
                        // Forward any internal watcher errors to the receiver
                        let _ = tx.send(Err(anyhow::anyhow!(error)));
                    }
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("Failed to create watcher: {e}"))?;

        if let Some(parent) = path.parent() {
            watcher
                .watch(parent, RecursiveMode::NonRecursive)
                .with_context(|| format!("Failed to watch parent directory {:?}", parent))?;
        }
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch file {:?}", path))?;

        Ok(FileWatcher {
            path,
            _watcher: watcher,
            rx,
        })
    }

    pub async fn recv(&mut self) -> Option<Result<(), anyhow::Error>> {
        self.rx.recv().await
    }
}

impl Drop for FileWatcher {
    fn drop(&mut self) {
        tracing::info!(?self.path, "File watcher task finished");
    }
}
