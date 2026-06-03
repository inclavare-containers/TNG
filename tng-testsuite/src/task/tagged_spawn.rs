use std::io;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Spawn a command with its stdout and stderr captured and re-emitted
/// with a `[tag]` prefix on each line.
///
/// The child process inherits stdin (set to null), while stdout and stderr
/// are piped through `BufReader::lines()` for real-time line-by-line tagging.
/// Background tokio tasks handle the streaming and will exit when the
/// process closes its pipes.
pub async fn spawn_with_tagged_output(cmd: &mut Command, tag: &str) -> io::Result<Child> {
    let tag = tag.to_owned();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Stream stdout with tag prefix
    if let Some(stdout) = child.stdout.take() {
        let tag_clone = tag.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                println!("[{}] {}", tag_clone, line);
            }
        });
    }

    // Stream stderr with tag prefix
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                eprintln!("[{}] {}", tag, line);
            }
        });
    }

    Ok(child)
}
