use std::collections::HashMap;

use crate::task::Task;
use anyhow::Result;

/// Returns a display name for a task, appending `@<ip>` only when
/// multiple tasks share the same base name.
pub fn display_name_for_task(task: &dyn Task, name_counts: &HashMap<String, usize>) -> String {
    let base = task.name();
    if name_counts.get(&base).copied().unwrap_or(0) > 1 {
        format!("{}@{}", base, task.node_type().ip())
    } else {
        base
    }
}

/// Log the start of an integration test with an ASCII boundary and task topology.
pub fn log_test_start(name: &str, tasks: &[&dyn Task], name_counts: &HashMap<String, usize>) {
    tracing::info!("========== Test Start: {name} ==========");

    if !tasks.is_empty() {
        tracing::info!("Task Topology:");
        for task in tasks {
            let display_name = display_name_for_task(*task, name_counts);
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
