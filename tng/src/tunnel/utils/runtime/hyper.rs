use std::future::Future;

impl<Fut> hyper::rt::Executor<Fut> for super::TokioRuntime
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[inline(always)]
    #[track_caller]
    fn execute(&self, fut: Fut) {
        let join_handle = self.spawn_supervised_task_current_span(fut);

        self.spawn_supervised_task_current_span(async move {
            let res = join_handle.await;
            tracing::debug!(is_err = res.is_err(), err=?res.err(), "task spawned for hyper finished")
        });
    }
}
