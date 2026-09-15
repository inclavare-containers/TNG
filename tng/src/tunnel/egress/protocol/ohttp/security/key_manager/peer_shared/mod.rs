mod cluster_key_set;
mod key_manager;
mod memberlist_rats_quic;
mod runtime;
mod serf;
mod serf_message;

// ClusterKeySet is exposed crate-wide (pub(crate)) so the file-exporting
// daemon's tests (the daemon now lives in the `tools` module) can build
// synthetic key sets without serf. Test-only: no production code outside
// `peer_shared` consumes it.
#[cfg(test)]
pub(crate) use cluster_key_set::ClusterKeySet;
pub use serf::PeerSharedKeyManager;
