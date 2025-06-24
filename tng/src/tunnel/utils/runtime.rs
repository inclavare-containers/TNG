/// This is a wrapper around tokio::runtime::Runtime, to handle the shutdown of the runtime when it is dropped.
/// It us shutdown_background() to make prevent the following error:
///
/// ```text
/// thread 'tokio-runtime-worker' panicked at /root/.cargo/registry/src/mirrors.ustc.edu.cn-4affec411d11e50f/tokio-1.45.1/src/runtime/blocking/shutdown.rs:51:21:
/// Cannot drop a runtime in a context where blocking is not allowed. This happens when a runtime is dropped from within an asynchronous context.
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
pub struct TokioRuntime {
    rt: Option<tokio::runtime::Runtime>,
    rt_handle: tokio::runtime::Handle,
}

impl TokioRuntime {
    pub fn new(rt: tokio::runtime::Runtime) -> Self {
        let rt_handle = rt.handle().clone();
        Self {
            rt: Some(rt),
            rt_handle: rt_handle,
        }
    }

    pub fn handle(&self) -> tokio::runtime::Handle {
        self.rt_handle.clone()
    }
}

impl Drop for TokioRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}
