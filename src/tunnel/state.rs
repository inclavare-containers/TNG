pub struct TngState {
    pub ready: (
        tokio::sync::watch::Sender<bool>,
        tokio::sync::watch::Receiver<bool>,
    ),
}

impl TngState {
    pub fn new() -> Self {
        TngState {
            ready: tokio::sync::watch::channel(false),
        }
    }
}
