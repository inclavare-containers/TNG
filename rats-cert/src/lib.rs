#![allow(incomplete_features)]
// To suppress warning messages appearing in recent nightly rust. See https://github.com/rust-lang/rust/issues/121315
#![allow(unused_imports)]

pub mod cert;
pub mod crypto;
pub mod errors;
pub mod tee;

#[cfg(test)]
mod tests {

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "debug".into());
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}
