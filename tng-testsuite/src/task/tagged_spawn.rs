use std::io;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::Instrument;

/// Spawn a command with its stdout and stderr captured and logged
/// via `tracing::info!` under the current tracing span.
///
/// The child process has its stdin set to null, while stdout and stderr
/// are piped through `BufReader::lines()` for real-time line-by-line logging.
/// Background tokio tasks handle the streaming and will exit when the
/// process closes its pipes.
///
/// **Note**: The stream tasks are fire-and-forget. If the parent cancels
/// the spawned task before the child process fully exits, some trailing
/// output may be lost. This is acceptable since this function is used
/// exclusively for debugging test output in the integration test framework.
pub async fn spawn_with_span_output(cmd: &mut Command) -> io::Result<Child> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Stream stdout with span prefix
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(
            async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    tracing::info!(target: "spawn", "{}", line);
                }
            }
            .instrument(tracing::Span::current()),
        );
    }

    // Stream stderr with span prefix
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(
            async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    tracing::info!(target: "spawn", "{}", line);
                }
            }
            .instrument(tracing::Span::current()),
        );
    }

    Ok(child)
}
