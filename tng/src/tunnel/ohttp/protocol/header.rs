#[derive(Debug, Clone)]
#[allow(unused)]
pub enum OhttpApi {
    KeyConfig,
    Tunnel,
    BackgroundCheckChallenge,
    BackgroundCheckVerify,
}

impl OhttpApi {
    pub const HEADER_NAME: &'static str = "x-tng-ohttp-api";
    /// - POST /tng/key-config: Get HPKE configuration
    pub const KEY_CONFIG: &'static str = "/tng/key-config";
    /// - POST /tng/tunnel: Process encrypted requests
    pub const TUNNEL: &'static str = "/tng/tunnel";
    /// - GET /tng/background-check/challenge: Get attestation challenge
    pub const BACKGROUND_CHECK_CHALLENGE: &'static str = "/tng/background-check/challenge";
    /// - POST /tng/background-check/verify: Verify attestation evidence
    pub const BACKGROUND_CHECK_VERIFY: &'static str = "/tng/background-check/verify";
}
