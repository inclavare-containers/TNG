use anyhow::bail;
use cidr::Ipv4Cidr;
use serde::{Deserialize, Serialize};
use serde_with::{formats::PreferMany, serde_as, OneOrMany};

use super::mapping_rule::MappingDe;
use super::ra::RaArgsUnchecked;
use super::UdpQuicArgs;
use crate::config::egress_hook::EgressHookArgs;
use crate::config::Endpoint;
use crate::tunnel::access_log::EgressAccessMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddEgressArgs {
    #[serde(flatten)]
    pub egress_mode: EgressMode,

    #[serde(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonArgs {
    #[serde(alias = "decap_from_http")]
    pub ohttp: Option<OHttpArgs>,

    #[serde(default = "Option::default")]
    pub direct_forward: Option<DirectForwardRules>,

    #[serde(default = "Option::default")]
    pub rats_tls: Option<RatsTlsArgs>,

    #[serde(default = "Option::default")]
    pub quic: Option<UdpQuicArgs>,

    #[serde(flatten)]
    pub ra_args: RaArgsUnchecked,
}

/// Configuration for rats-TLS transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RatsTlsArgs {
    /// When `true`, uses HTTP/2 CONNECT tunneling to multiplex multiple
    /// TCP streams over a single rats-TLS connection, reducing handshake overhead.
    /// Suitable for many short-lived connections with small data transfers.
    /// When `false` (default), each downstream connection creates an independent TLS
    /// session without HTTP/2 CONNECT or connection pooling, achieving higher
    /// per-stream throughput — recommended for high-bandwidth scenarios.
    /// Note: with `multiplex: true`, all streams share a single TLS connection
    /// whose bandwidth is limited by the TLS encryption capacity of one CPU core.
    #[serde(default)]
    pub multiplex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectForwardRules(pub Vec<DirectForwardRule>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectForwardRule {
    pub http_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EgressMappingArgs {
    /// Parsed rules: either from the new `rules` array, or a single rule
    /// synthesized from the legacy `in`/`out` fields.
    pub rules: Vec<super::mapping_rule::MappingRule>,
}

impl<'de> Deserialize<'de> for EgressMappingArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let de = MappingDe::deserialize(deserializer)?;
        let rules = de
            .into_checked("egress mapping")
            .map_err(serde::de::Error::custom)?;
        Ok(Self { rules })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressMappingUdpArgs {
    /// QUIC listener address.
    #[serde(rename = "in")]
    pub r#in: Endpoint,

    /// Backend UDP service address.
    pub out: Endpoint,

    /// Idle timeout in seconds for the UDP session.
    ///
    /// This is a bidirectional timeout — both directions must be idle for the
    /// timeout to trigger. Any activity in either direction resets the timer.
    ///
    /// If no datagram is sent from QUIC AND no response datagram is received
    /// from the backend for this duration, the UDP socket is closed and the
    /// corresponding QUIC connection is terminated.
    ///
    /// Similar to NAT UDP session timeout. Defaults to 30s if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressNetfilterArgs {
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_dst: Vec<EgressNetfilterCaptureDstArgs>,

    #[serde(default = "bool::default")]
    pub capture_local_traffic: bool,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_cgroup: Vec<String>,

    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nocapture_cgroup: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub so_mark: Option<u32>,
}

/// Instead of using the EgressNetfilterCaptureDst directly, here we define a common struct for json parsing to get better deserialization error message.
/// See https://github.com/serde-rs/serde/issues/2157
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressNetfilterCaptureDstArgs {
    host: Option<Ipv4Cidr>,
    ipset: Option<String>,
    port: Option<u16>,

    /// Optional end port for port range matching.
    /// When set together with `port`, iptables will use `--dport port:port_end` syntax
    /// to match a contiguous range of destination ports [port, port_end].
    port_end: Option<u16>,
}

impl TryFrom<EgressNetfilterCaptureDstArgs> for EgressNetfilterCaptureDst {
    type Error = anyhow::Error;

    fn try_from(value: EgressNetfilterCaptureDstArgs) -> Result<Self, Self::Error> {
        let port_end = value.port_end;
        if let Some(end) = port_end {
            let Some(port) = value.port else {
                bail!("`port_end` requires `port` to be specified");
            };
            if end < port {
                bail!("`port_end` ({end}) must be >= `port` ({port})");
            }
        }
        Ok(match (value.host, value.ipset, value.port) {
            (None, None, None) => bail!("one of host, ipset, port must be specified"),
            (None, None, Some(port)) => EgressNetfilterCaptureDst::PortOnly { port, port_end },
            (None, Some(ipset), None) => EgressNetfilterCaptureDst::IpSetOnly { ipset },
            (None, Some(ipset), Some(port)) => EgressNetfilterCaptureDst::IpSetAndPort {
                ipset,
                port,
                port_end,
            },
            (Some(host), None, None) => EgressNetfilterCaptureDst::HostOnly { host },
            (Some(host), None, Some(port)) => EgressNetfilterCaptureDst::HostAndPort {
                host,
                port,
                port_end,
            },
            (Some(_), Some(_), _) => bail!("Only one of host or ipset can be specified"),
        })
    }
}

pub enum EgressNetfilterCaptureDst {
    HostOnly {
        host: Ipv4Cidr,
    },
    IpSetOnly {
        ipset: String,
    },
    PortOnly {
        port: u16,
        port_end: Option<u16>,
    },
    HostAndPort {
        host: Ipv4Cidr,
        port: u16,
        port_end: Option<u16>,
    },
    IpSetAndPort {
        ipset: String,
        port: u16,
        port_end: Option<u16>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EgressMode {
    #[serde(rename = "mapping")]
    Mapping(EgressMappingArgs),

    #[serde(rename = "netfilter")]
    Netfilter(EgressNetfilterArgs),

    #[serde(rename = "hook")]
    Hook(EgressHookArgs),

    #[cfg(feature = "egress-mapping-udp")]
    #[serde(rename = "mapping_udp")]
    MappingUdp(EgressMappingUdpArgs),
}

impl EgressMode {
    pub fn access_mode(&self) -> EgressAccessMode {
        match self {
            EgressMode::Mapping(_) => EgressAccessMode::Mapping,
            EgressMode::Netfilter(_) => EgressAccessMode::Netfilter,
            EgressMode::Hook(_) => EgressAccessMode::Hook,
            #[cfg(feature = "egress-mapping-udp")]
            EgressMode::MappingUdp(_) => EgressAccessMode::MappingUdp,
        }
    }
}

/// Configuration for OHTTP (Oblivious HTTP) support in TNG.
///
/// This struct controls how the TNG endpoint handles OHTTP-encapsulated traffic,
/// including cross-origin settings and key management strategy.
///
/// By default, if not explicitly configured, OHTTP is disabled.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

    /// Controls which headers from the upstream response are copied to the
    /// outer OHTTP HTTP response.
    #[serde(default)]
    pub header_passthrough: Option<EgressHeaderPassthroughConfig>,
}

/// Defines the strategy for obtaining the HPKE private key used in OHTTP decryption.
///
/// This is a tagged enum (`source` field) that specifies the key management model.
/// Only one variant can be active at a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source")]
#[allow(clippy::large_enum_variant)]
pub enum KeyArgs {
    /// The TNG instance generates its own HPKE key pair (X25519) at startup
    /// and automatically rotates it on a periodic basis.
    #[serde(rename = "self_generated")]
    SelfGenerated {
        /// Interval (in seconds) between automatic key rotations.
        ///
        /// Optional. Defaults to 300 seconds (5 minutes).
        rotation_interval: u64,
    },

    /// Load the HPKE private key from a PEM file on disk.
    ///
    /// Recommended for integration with external secret managers.
    #[serde(rename = "file")]
    File {
        /// Path to the PKCS#8 encoded X25519 private key file.
        path: String,
    },

    #[serde(rename = "peer_shared")]
    PeerShared(PeerSharedArgs),
}

/// Enable decentralized key sharing among TNG peers.
///
/// Each node generates its own key and securely shares it with other nodes
/// via authenticated, encrypted peer-to-peer channels.
/// All nodes maintain a local "key ring" of valid private keys from all peers,
/// allowing any node to decrypt requests encrypted under any peer's public key.
///
/// This mode requires:
/// - A list of initial peers to join the network
/// - Remote attestation setup for mutual identity verification
///
/// Example:
/// ```json
/// "key": {
///   "source": "peer_shared",
///   "peers": [
///     "192.168.10.1:8301",
///     "tng-service.default.svc.cluster.local:8301"
///   ],
///   "rotation_interval": 300,
///   "attest": {
///     "model": "background_check",
///     "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
///   },
///   "verify": {
///     "model": "background_check",
///     "as_addr": "http://as.example.com:8080/",
///     "as_is_grpc": false,
///     "policy_ids": ["default"]
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSharedArgs {
    /// Interval (in seconds) between automatic key rotations.
    ///
    /// Each node independently rotates its own key.
    /// Old keys are retained for up to 2 * rotation_interval to ensure availability.
    pub rotation_interval: u64,

    /// Listen address used for inter-node secure communication (default: 0.0.0.0)
    #[serde(default = "default_peer_host")]
    pub host: String,

    /// Listen port used for inter-node secure communication (default: 8301)
    #[serde(default = "default_peer_port")]
    pub port: u16,

    /// List of initial peer addresses (IP:port or DNS name) to discover and connect to.
    ///
    /// At least one peer should be reachable to join the cluster.
    #[serde(default = "Default::default")]
    pub peers: Vec<String>,

    /// Optional file path that contains a JSON array of peer addresses.
    /// This allows dynamic updates to the peer list without restarting the service.
    #[serde(default = "Default::default")]
    pub peers_file: Option<String>,

    /// Define how this node proves its identity when connecting to others, and how to verify
    /// the identity of remote peers.
    #[serde(flatten)]
    pub ra_args: RaArgsUnchecked,
}

fn default_peer_host() -> String {
    "0.0.0.0".into()
}

fn default_peer_port() -> u16 {
    8301
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

/// Configuration for copying selected headers from the upstream plaintext
/// response to the outer OHTTP HTTP response.
///
/// These headers are visible to intermediaries between Egress and Ingress
/// but are NOT forwarded to the downstream client — they remain encrypted
/// inside the OHTTP body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EgressHeaderPassthroughConfig {
    /// Header names to copy from the upstream response to the outer response.
    #[serde(default)]
    pub response_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use crate::config::TngConfig;

    use super::{EgressMode, EgressNetfilterCaptureDst, EgressNetfilterCaptureDstArgs};

    fn test_deserialize_egress_netfilter_common(value: serde_json::Value) -> Result<()> {
        let config: TngConfig = serde_json::from_value(value)?;
        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_egress_netfilter_array_format() -> Result<()> {
        // New array format
        test_deserialize_egress_netfilter_common(json!(
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                { "port": 30001 },
                                { "host": "127.0.0.1" },
                                { "host": "127.0.0.1", "port": 30002 },
                                { "host": "10.1.1.0/24", "port": 30002 },
                            ],
                            "listen_port": 50000
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    #[test]
    fn test_deserialize_egress_netfilter_backward_compat() -> Result<()> {
        // Old single-object format (backward compatibility via OneOrMany)
        test_deserialize_egress_netfilter_common(json!(
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 9991
                            }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    #[test]
    fn test_deserialize_egress_netfilter_cgroup() -> Result<()> {
        // cgroup-based capture
        test_deserialize_egress_netfilter_common(json!(
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_cgroup": ["/system.slice/vllm.service"],
                            "nocapture_cgroup": ["/system.slice/ssh.service"]
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    #[test]
    fn test_deserialize_egress_netfilter_capture_all() -> Result<()> {
        // Empty capture_dst = capture all TCP traffic
        test_deserialize_egress_netfilter_common(json!(
            {
                "add_egress": [
                    {
                        "netfilter": {},
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
        ))?;
        Ok(())
    }

    fn test_deserialize_capture_dst_common(value: serde_json::Value) -> Result<()> {
        EgressNetfilterCaptureDst::try_from(serde_json::from_value::<
            EgressNetfilterCaptureDstArgs,
        >(value)?)?;
        Ok(())
    }

    #[test]
    fn test_deserialize_egress_capture_dst_modes() -> Result<()> {
        // HostOnly
        test_deserialize_capture_dst_common(serde_json::json!({ "host": "10.1.1.0/24" }))?;

        // IpSetOnly
        test_deserialize_capture_dst_common(serde_json::json!({ "ipset": "vllm_ports" }))?;

        // PortOnly
        test_deserialize_capture_dst_common(serde_json::json!({ "port": 30002 }))?;

        // HostAndPort
        test_deserialize_capture_dst_common(serde_json::json!({
            "host": "10.1.1.0/24",
            "port": 30002
        }))?;

        // IpSetAndPort
        test_deserialize_capture_dst_common(serde_json::json!({
            "ipset": "vllm_ports",
            "port": 30002
        }))?;

        // Invalid: both host and ipset
        assert!(test_deserialize_capture_dst_common(serde_json::json!({
            "host": "10.1.1.0/24",
            "ipset": "vllm_ports",
            "port": 30002
        }))
        .is_err());

        // Invalid: both host and ipset, no port
        assert!(test_deserialize_capture_dst_common(serde_json::json!({
            "host": "10.1.1.0/24",
            "ipset": "vllm_ports",
        }))
        .is_err());

        // Invalid: empty
        assert!(test_deserialize_capture_dst_common(serde_json::json!({})).is_err());

        // PortOnly with port_end
        test_deserialize_capture_dst_common(serde_json::json!({
            "port": 30000,
            "port_end": 30031
        }))?;

        // Invalid: port_end without port
        assert!(test_deserialize_capture_dst_common(serde_json::json!({
            "host": "10.1.1.0/24",
            "port_end": 30031
        }))
        .is_err());

        // Invalid: port_end < port
        assert!(test_deserialize_capture_dst_common(serde_json::json!({
            "port": 30031,
            "port_end": 30000
        }))
        .is_err());

        Ok(())
    }

    #[test]
    fn test_deserialize_egress_mapping_backward_compat() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "no_ra": true
                    }
                ]
            }
        ))?;
        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;
        assert_eq!(
            serde_json::to_value(&config)?,
            serde_json::to_value(&config2)?
        );
        if let EgressMode::Mapping(m) = &config.add_egress[0].egress_mode {
            assert_eq!(m.rules.len(), 1);
            assert_eq!(m.rules[0].r#in.port, 20001);
            assert_eq!(m.rules[0].out.port, 30001);
        } else {
            panic!("expected mapping mode");
        }
        Ok(())
    }

    #[test]
    fn test_deserialize_egress_mapping_port_range() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_egress": [
                    {
                        "mapping": {
                            "rules": [
                                {
                                    "in": { "host": "0.0.0.0", "port": 20010, "port_end": 20020 },
                                    "out": { "host": "127.0.0.1", "port": 30010, "port_end": 30020 }
                                }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ))?;
        if let EgressMode::Mapping(m) = &config.add_egress[0].egress_mode {
            assert_eq!(m.rules[0].r#in.port_end, Some(20020));
            assert_eq!(m.rules[0].out.port_end, Some(30020));
        } else {
            panic!("expected mapping mode");
        }
        Ok(())
    }

    #[test]
    fn test_egress_mapping_validation_overlapping_rules() {
        let result = serde_json::from_value::<TngConfig>(json!(
            {
                "add_egress": [
                    {
                        "mapping": {
                            "rules": [
                                { "in": { "host": "0.0.0.0", "port": 20010, "port_end": 20020 }, "out": { "host": "127.0.0.1", "port": 30010, "port_end": 30020 } },
                                { "in": { "host": "0.0.0.0", "port": 20015, "port_end": 20025 }, "out": { "host": "127.0.0.1", "port": 30015, "port_end": 30025 } }
                            ]
                        },
                        "no_ra": true
                    }
                ]
            }
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("overlapping"),
            "error should mention overlapping: {err}"
        );
    }

    #[test]
    fn test_deserialize_egress_hook() -> Result<()> {
        use serde_json::json;

        let value = json!({
            "add_egress": [
                {
                    "hook": {
                        "capture_listen": [
                            { "port": 30001 },
                            { "host": "192.168.1.1", "port": 30002, "redirect_to_port": 45002 }
                        ]
                    },
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }
            ]
        });

        let config: TngConfig = serde_json::from_value(value.clone())?;
        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;
        assert_eq!(
            serde_json::to_value(&config)?,
            serde_json::to_value(config2)?
        );

        // Verify the hook config was parsed correctly
        let hook = match &config.add_egress[0].egress_mode {
            EgressMode::Hook(args) => args,
            _ => panic!("expected hook mode"),
        };
        assert_eq!(hook.capture_listen.len(), 2);
        assert_eq!(hook.capture_listen[0].port, Some(30001));
        assert_eq!(hook.capture_listen[1].redirect_to_port, Some(45002));

        Ok(())
    }

    #[test]
    fn test_deserialize_egress_hook_port_range() -> Result<()> {
        use serde_json::json;

        let config: TngConfig = serde_json::from_value(json!({
            "add_egress": [
                {
                    "hook": {
                        "capture_listen": [
                            { "port": 8080, "port_end": 8090, "redirect_to_port": 48080, "redirect_to_port_end": 48090 }
                        ]
                    },
                    "attest": {
                        "no_ra": true,
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }
            ]
        }))?;

        let hook = match &config.add_egress[0].egress_mode {
            EgressMode::Hook(args) => args,
            _ => panic!("expected hook mode"),
        };
        assert_eq!(hook.capture_listen.len(), 1);
        let entry = &hook.capture_listen[0];
        assert_eq!(entry.port, Some(8080));
        assert_eq!(entry.port_end, Some(8090));
        assert_eq!(entry.redirect_to_port, Some(48080));
        assert_eq!(entry.redirect_to_port_end, Some(48090));
        assert!(entry.host.is_none());

        // Round-trip
        let config_json = serde_json::to_string_pretty(&config)?;
        let config2: TngConfig = serde_json::from_str(&config_json)?;
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(config2)?
        );

        Ok(())
    }
}
