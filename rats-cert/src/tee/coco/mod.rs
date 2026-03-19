#[cfg(feature = "attester-coco")]
pub mod attester;
#[cfg(feature = "verifier-coco")]
pub mod converter;
#[cfg(any(feature = "attester-coco", feature = "verifier-coco"))]
pub mod evidence;
#[cfg(feature = "verifier-coco")]
pub mod verifier;

#[cfg(feature = "attester-coco")]
pub const TTRPC_DEFAULT_TIMEOUT_NANO: i64 = 50 * 1000 * 1000 * 1000;
