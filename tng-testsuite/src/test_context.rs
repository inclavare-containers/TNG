use crate::task::Task;
use anyhow::Result;

/// Log the start of an integration test with an ASCII boundary and task topology.
pub fn log_test_start(name: &str, tasks: &[&dyn Task]) {
    tracing::info!("========== 开始测试: {name} ==========");

    if !tasks.is_empty() {
        tracing::info!("任务拓扑:");
        for task in tasks {
            let node_type = task.node_type();
            let ip = node_type.ip();
            tracing::info!("  [{}] {:?} @ {}", task.name(), node_type, ip);
        }
    }
}

/// Log the end of an integration test with pass/fail status.
pub fn log_test_end(name: &str, result: &Result<()>) {
    let status = match result {
        Ok(()) => "PASS",
        Err(_) => "FAIL",
    };
    tracing::info!("========== 测试结束: {name} ({status}) ==========");
}
