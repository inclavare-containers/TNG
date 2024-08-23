pub mod egress;
pub mod ingress;

pub const ENVOY_DUMMY_CERT: &'static str = include_str!("servercert.pem");
pub const ENVOY_DUMMY_KEY: &'static str = include_str!("serverkey.pem");

pub const ENVOY_LISTENER_SOCKET_OPTIONS: &'static str = r#"
    - description: SO_KEEPALIVE
      int_value: 1
      level: 1
      name: 9
      state: STATE_PREBIND
    - description: TCP_KEEPIDLE
      int_value: 30
      level: 6
      name: 4
      state: STATE_PREBIND
    - description: TCP_KEEPINTVL
      int_value: 10
      level: 6
      name: 5
      state: STATE_PREBIND
    - description: TCP_KEEPCNT
      int_value: 5
      level: 6
      name: 6
      state: STATE_PREBIND
"#;

pub const ENVOY_HTTP2_CONNECT_WRAPPER_STREAM_IDLE_TIMEOUT: &'static str = "3600s"; // 1 hour

pub const ENVOY_L7_RESPONSE_BODY_DENIED: &'static str = "This service is secured by TNG secure session and you must establish the connection via TNG.\n\nIf this is an unexpected behavior, set `allow_non_tng_traffic=true`.";
