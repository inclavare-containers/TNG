use std::sync::Arc;

use anyhow::Result;

/// This is a wrapper around tokio::runtime::Runtime, to handle the shutdown of the runtime when it is dropped.
/// It us shutdown_background() to make prevent the following error:
///
/// ```text
/// thread 'tokio-runtime-worker' panicked at /root/.cargo/registry/src/mirrors.ustc.edu.cn-4affec411d11e50f/tokio-1.45.1/src/runtime/blocking/shutdown.rs:51:21:
/// Cannot drop a runtime in a context where blocking is not allowed. This happens when a runtime is dropped from within an asynchronous context.
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
#[derive(Debug)]
pub struct TokioRuntime {
    #[cfg(unix)]
    rt: Option<tokio::runtime::Runtime>,
    #[cfg(unix)]
    rt_handle: tokio::runtime::Handle,
}

impl TokioRuntime {
    #[cfg(unix)]
    #[allow(dead_code)]
    pub fn new_multi_thread() -> Result<Self> {
        use anyhow::Context;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;
        let rt_handle = rt.handle().clone();
        Ok(Self {
            rt: Some(rt),
            rt_handle: rt_handle,
        })
    }

    #[cfg(unix)]
    #[allow(dead_code)]
    pub fn current() -> Result<Self> {
        let rt_handle = tokio::runtime::Handle::try_current()?;
        Ok(Self {
            rt: None,
            rt_handle: rt_handle,
        })
    }

    #[cfg(wasm)]
    #[allow(dead_code)]
    pub fn wasm_main_thread() -> Result<Self> {
        Ok(Self {})
    }

    #[cfg(unix)]
    pub fn tokio_rt_handle(&self) -> &tokio::runtime::Handle {
        &self.rt_handle
    }

    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl Drop for TokioRuntime {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}
