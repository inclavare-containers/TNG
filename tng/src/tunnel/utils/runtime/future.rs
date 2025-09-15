#[cfg(unix)]
pub trait TokioRuntimeSupportedFuture<O>: std::future::Future<Output = O> + Send + 'static {}

#[cfg(unix)]
impl<T, O> TokioRuntimeSupportedFuture<O> for T where
    T: std::future::Future<Output = O> + Send + 'static
{
}

#[cfg(wasm)]
pub trait TokioRuntimeSupportedFuture<O>: std::future::Future<Output = O> + 'static {}

#[cfg(wasm)]
impl<T, O> TokioRuntimeSupportedFuture<O> for T where T: std::future::Future<Output = O> + 'static {}
