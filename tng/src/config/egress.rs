use serde::{Deserialize, Serialize};

use super::{ra::RaArgsUnchecked, Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddEgressArgs {
    #[serde(flatten)]
    pub egress_mode: EgressMode,

    #[serde(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommonArgs {
    #[serde(alias = "decap_from_http")]
    pub ohttp: Option<OHttpArgs>,

    #[serde(default = "Option::default")]
    pub direct_forward: Option<DirectForwardRules>,

    #[serde(flatten)]
    pub ra_args: RaArgsUnchecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectForwardRules(pub Vec<DirectForwardRule>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectForwardRule {
    pub http_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressMappingArgs {
    pub r#in: Endpoint,
    pub out: Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressNetfilterArgs {
    pub capture_dst: Endpoint,

    #[serde(default = "bool::default")]
    pub capture_local_traffic: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub so_mark: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum EgressMode {
    #[serde(rename = "mapping")]
    Mapping(EgressMappingArgs),

    #[serde(rename = "netfilter")]
    Netfilter(EgressNetfilterArgs),
}

/// Configuration for OHTTP (Oblivious HTTP) support in TNG.
///
/// This struct controls how the TNG endpoint handles OHTTP-encapsulated traffic,
/// including cross-origin settings and key management strategy.
///
/// By default, if not explicitly configured, OHTTP is disabled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct OHttpArgs {
    /// **(Deprecated)** Regular expressions matching paths that are allowed to bypass
    /// OHTTP decryption and be forwarded as plaintext.
    ///
    /// This field has been deprecated since v2.2.4. Use `direct_forward` at the egress
    /// level instead to specify non-OHTTP traffic rules.
    ///
    /// Example (deprecated):
    /// ```json
    /// "allow_non_tng_traffic_regexes": ["/healthz", "/ready"]
    /// ```
    #[serde(default = "Option::default")]
    pub allow_non_tng_traffic_regexes: Option<AllowNonTngTrafficRegexes>,

    /// CORS configuration for the OHTTP server endpoint.
    ///
    /// Allows browser-based clients to access the OHTTP endpoint by setting appropriate
    /// CORS headers (`Access-Control-Allow-*`). Only affects HTTP responses to preflight
    /// (OPTIONS) and actual requests when the `Origin` header is present.
    ///
    /// If not specified, CORS headers are not added, and browser requests may be blocked.
    ///
    /// Example:
    /// ```json
    /// "cors": {
    ///   "allow_origins": ["https://example.com"],
    ///   "allow_methods": ["POST"],
    ///   "allow_headers": ["Content-Type"]
    /// }
    /// ```
    #[serde(default = "Option::default")]
    pub cors: Option<CorsConfig>,

    /// Configuration for the local HPKE private key used to decrypt incoming OHTTP requests.
    ///
    /// Specifies how the TNG instance obtains its private key. Currently supports:
    ///
    /// - `"self_generated"`: The node generates its own key pair and rotates it periodically.
    ///   This is the **default mode**.
    ///
    /// Future extensions may support:
    /// - File-based key loading
    /// - Gossip-based key distribution across a cluster
    ///
    /// The selected strategy determines whether keys are shared across instances
    /// or isolated per-node.
    ///
    /// Example (default behavior):
    /// ```json
    /// "key": {
    ///   "source": "self_generated",
    ///   "rotation_interval": 300
    /// }
    /// ```
    #[serde(default = "Default::default")]
    pub key: KeyArgs,
}

/// Defines the strategy for obtaining the HPKE private key used in OHTTP decryption.
///
/// This is a tagged enum (`source` field) that specifies the key management model.
/// Only one variant can be active at a time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source")]
pub enum KeyArgs {
    /// The TNG instance generates its own HPKE key pair (X25519) at startup
    /// and automatically rotates it on a periodic basis.
    ///
    /// This is the **default and recommended mode** for standalone or development deployments.
    ///
    /// - A new key is generated every `rotation_interval` seconds.
    /// - Old keys are retained briefly (grace period) to handle delayed or replayed requests.
    /// - Each node operates independently; clients must fetch updated public keys regularly.
    ///
    /// Example:
    /// ```json
    /// "key": {
    ///   "source": "self_generated",
    ///   "rotation_interval": 300
    /// }
    /// ```
    #[serde(rename = "self_generated")]
    SelfGenerated {
        /// Interval (in seconds) between automatic key rotations.
        ///
        /// Optional. If not provided, defaults to 300 seconds (5 minutes).
        ///
        /// Smaller values increase security but may cause more frequent client re-fetching
        /// of the `/tng/key-config` endpoint.
        rotation_interval: u64,
    },
}

// Default: rotate self-generated OHTTP keys every 5 minutes.
const DEFAULT_SELF_GENERATED_KEY_ROTATION_INTERVAL_SECOND: u64 = 5 * 60;

impl Default for KeyArgs {
    fn default() -> Self {
        Self::SelfGenerated {
            rotation_interval: DEFAULT_SELF_GENERATED_KEY_ROTATION_INTERVAL_SECOND,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allow origins for CORS, e.g. ["https://example.com", "https://app.example.com"]
    #[serde(default)]
    pub allow_origins: Vec<String>,

    /// Allow methods for CORS, e.g. ["GET", "POST", "OPTIONS"]
    #[serde(default)]
    pub allow_methods: Vec<String>,

    /// Allow headers for CORS, e.g. ["Content-Type", "Authorization"]
    #[serde(default)]
    pub allow_headers: Vec<String>,

    /// Expose headers for CORS, e.g. ["X-Custom-Header"]
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// Allow credentials for CORS
    #[serde(default)]
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct AllowNonTngTrafficRegexes(Vec<String>);

impl From<AllowNonTngTrafficRegexes> for DirectForwardRules {
    fn from(value: AllowNonTngTrafficRegexes) -> Self {
        Self(
            value
                .0
                .into_iter()
                .map(|s| DirectForwardRule { http_path: s })
                .collect(),
        )
    }
}
