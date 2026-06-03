use crate::task::Task;
use anyhow::Result;

/// Returns a display name for a task, always including the node IP.
/// Format: `{name}@{ip}` (e.g., `tng_server@192.168.1.1`).
pub fn display_name_for_task(task: &dyn Task) -> String {
    format!("{}@{}", task.name(), task.node_type().ip())
}

/// Log the start of an integration test with an ASCII boundary and task topology.
pub fn log_test_start(name: &str, tasks: &[&dyn Task]) {
    tracing::info!("========== Test Start: {name} ==========");

    if !tasks.is_empty() {
        tracing::info!("Task Topology:");
        for task in tasks {
            let display_name = display_name_for_task(*task);
            let node_type = task.node_type();
            let ip = node_type.ip();
            tracing::info!("  [{display_name}] {node_type} @ {ip}");
        }
    }
}

/// Log the end of an integration test with pass/fail status.
pub fn log_test_end(name: &str, result: &Result<()>) {
    let status = match result {
        Ok(()) => "PASS",
        Err(_) => "FAIL",
    };
    tracing::info!("========== Test End: {name} ({status}) ==========");
}
