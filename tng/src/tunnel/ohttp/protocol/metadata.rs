#![allow(clippy::module_inception)]
include!(concat!(env!("OUT_DIR"), "/tng.ohttp.metadata.rs"));

pub const METADATA_MAX_LEN: usize = 32 * 1024 * 1024; // 32MB
