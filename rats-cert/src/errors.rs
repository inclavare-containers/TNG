use thiserror::Error;

use crate::tee::coco::converter::{grpc::GrpcAsVersion, restful::RestfulAsApiVersion};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to convert TEE type to string: {0:?}")]
    TeeTypeToStringFailed(kbs_types::Tee),

    #[error("Failed to parse TEE type from string: {tee_type}")]
    TeeTypeFromStringFailed { tee_type: String },

    #[error("Failed to parse evidence from DICE cert: {detail}")]
    DiceParseEvidenceFailed { detail: String },

    // Token verification related
    #[error("Unsupported EAT profile: {profile}")]
    UnsupportedEatProfile { profile: String },

    #[error("Missing field in token: {detail}")]
    MissingTokenField { detail: String },

    #[error("Runtime data mismatch")]
    RuntimeDataMismatch,

    #[error("EAR status is not affirming: got {status} for {tee_type}, trustworthiness: {trustworthiness}")]
    EarStatusNotAffirming {
        status: String,
        tee_type: String,
        trustworthiness: String,
    },

    #[error("Multiple policy IDs found in EAR token")]
    MultiplePolicyIds,

    #[error("No valid policy ID found in EAR token")]
    NoValidPolicyId,

    #[error("Policy evaluation failed for policy_id `{policy_id}`")]
    PolicyEvaluationFailed { policy_id: String },

    // Remote AS related
    #[error("Remote AS gRPC is not supported")]
    RemoteAsGrpcNotSupported,

    #[error("No trust source provided (neither trusted_certs_paths nor as_addr)")]
    NoTrustSource,

    // gRPC AS related errors
    #[cfg(not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )))]
    #[error("Failed to create gRPC endpoint for AS address `{as_addr}`")]
    GrpcEndpointCreateFailed {
        as_addr: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[cfg(not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )))]
    #[error("Failed to connect to gRPC AS address `{as_addr}`")]
    GrpcConnectFailed {
        as_addr: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("gRPC attestation evaluate failed (api_version: {0:?})")]
    AttestationServiceGrpcAttestationEvaluateFailed(GrpcAsVersion, #[source] tonic::Status),

    // AA ttrpc related errors
    #[cfg(feature = "attester-coco")]
    #[error("Failed to get evidence from Attestation Agent")]
    GetEvidenceFromAAFailed(#[source] ttrpc::Error),

    #[cfg(feature = "attester-coco")]
    #[error("Failed to get TEE type from Attestation Agent")]
    GetTeeTypeFromAAFailed(#[source] ttrpc::Error),

    #[cfg(feature = "attester-coco")]
    #[error("Failed to connect to Attestation Agent ttrpc endpoint")]
    ConnectAttestationAgentTtrpcFailed(#[source] ttrpc::Error),

    #[error("Coco token verifier error")]
    CocoTokenVerifierError(#[source] crate::tee::coco::verifier::token::Error),

    #[error("Signer transparency verification failed: {detail}")]
    SignerTransparencyVerificationFailed { detail: String },

    // Built-in AS related
    // Certificate generation related errors
    #[error("Failed to generate certificate validity period")]
    CertValidityGenerationFailed(#[source] pkcs8::der::Error),

    #[error("Failed to parse certificate subject {0}")]
    CertSubjectParseFailed(String, #[source] pkcs8::der::Error),

    #[error("Failed to create SubjectPublicKeyInfo")]
    CertSpkiCreationFailed(#[source] pkcs8::spki::Error),

    #[error("Failed to build certificate")]
    CertBuildFailed(#[source] x509_cert::builder::Error),

    #[error("Failed to sign certificate")]
    CertSignFailed(#[source] x509_cert::builder::Error),

    #[error("Failed to encode certificate")]
    CertEncodeFailed(#[source] pkcs8::der::Error),

    #[cfg(feature = "__builtin-as")]
    #[error("Failed to generate CA certificate")]
    CaCertGenerationFailed(#[source] rcgen::Error),

    #[cfg(feature = "__builtin-as")]
    #[error("Failed to generate AS certificate")]
    AsCertGenerationFailed(#[source] rcgen::Error),

    #[cfg(feature = "__builtin-as")]
    #[error("Failed to create builtin attestation service working directory")]
    BuilinAttestationServiceCreateWorkDirFailed(#[source] std::io::Error),

    #[error("Failed to write AS private key to {path}")]
    WriteAsPrivateKeyFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write certificate chain to {path}")]
    WriteCertChainFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read policy file from {path}")]
    ReadPolicyFileFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read reference value file from {path}")]
    ReadReferenceValueFileFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Base64 decode failed")]
    Base64DecodeFailed(#[source] base64::DecodeError),

    // Reference value errors (specific scenarios)
    #[error("Failed to parse reference value payload from {path}")]
    ParseReferenceValuePayloadFailed {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to serialize reference value message")]
    SerializeReferenceValueMessageFailed(#[source] serde_json::Error),

    #[error("Failed to register sample reference value")]
    RegisterSampleReferenceValueFailed(#[source] anyhow::Error),

    #[error("Failed to set SLSA reference value list")]
    SetSlsaReferenceValueListFailed(#[source] anyhow::Error),

    // RSA key generation
    #[error("RSA key generation failed")]
    RsaKeyGenerationFailed(#[source] rsa::Error),

    // CBOR serialization/deserialization
    #[error("CBOR serialization failed")]
    CborSerializationFailed(#[source] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR deserialization failed")]
    CborDeserializationFailed(#[source] ciborium::de::Error<std::io::Error>),

    // UTF-8 conversion
    #[error("Invalid UTF-8 sequence in string")]
    InvalidUtf8(#[source] std::string::FromUtf8Error),

    #[error("Invalid UTF-8 sequence in byte slice")]
    InvalidUtf8Slice(#[source] std::str::Utf8Error),

    // TEE type
    #[error("Unknown TEE type: {tee_type}")]
    UnknownTeeType { tee_type: String },

    // gRPC metadata
    #[error("Invalid gRPC metadata key")]
    InvalidGrpcMetadataKey(#[source] tonic::metadata::errors::InvalidMetadataKey),

    #[error("Invalid gRPC metadata value")]
    InvalidGrpcMetadataValue(#[source] tonic::metadata::errors::InvalidMetadataValue),

    // Attestation service operations
    #[cfg(feature = "__builtin-as")]
    #[error("Failed to create attestation service")]
    AttestationServiceCreateFailed(#[source] attestation_service::ServiceError),

    #[cfg(feature = "__builtin-as")]
    #[error("Failed to set attestation policy")]
    AttestationServiceSetPolicyFailed(#[source] anyhow::Error),

    #[cfg(feature = "__builtin-as")]
    #[error("Failed to generate attestation challenge")]
    AttestationServiceGenerateChallengeFailed(#[source] anyhow::Error),

    #[cfg(feature = "__builtin-as")]
    #[error("Attestation evidence verification failed")]
    AttestationServiceVerifyFailed(#[source] anyhow::Error),

    // HTTP client building
    #[error("Failed to build HTTP client")]
    AttestationServiceHttpClientBuildFailed(#[source] reqwest::Error),

    #[error("Failed to send /challenge HTTP request to AS (api_version: {0:?})")]
    AttestationServiceChallengeHttpRequestSendFailed(RestfulAsApiVersion, #[source] reqwest::Error),

    #[error("Failed to send /attestation HTTP request to AS (api_version: {0:?})")]
    AttestationServiceAttestationHttpRequestSendFailed(
        RestfulAsApiVersion,
        #[source] reqwest::Error,
    ),

    #[error("Failed to read /challenge HTTP response from AS (api_version: {0:?})")]
    AttestationServiceChallengeHttpResponseReadFailed(
        RestfulAsApiVersion,
        #[source] reqwest::Error,
    ),

    #[error("Failed to read /attestation HTTP response from AS (api_version: {0:?})")]
    AttestationServiceAttestationHttpResponseReadFailed(
        RestfulAsApiVersion,
        #[source] reqwest::Error,
    ),

    #[error(
        "Attestation service /challenge returned HTTP error (api_version: {api_version:?}): status={status_code}, response={response_body}"
    )]
    AttestationServiceChallengeHttpResponseError {
        api_version: RestfulAsApiVersion,
        status_code: u16,
        response_body: String,
    },

    #[error(
        "Attestation service /attestation returned HTTP error (api_version: {api_version:?}): status={status_code}, response={response_body}"
    )]
    AttestationServiceAttestationHttpResponseError {
        api_version: RestfulAsApiVersion,
        status_code: u16,
        response_body: String,
    },

    // Task spawning
    #[cfg(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))]
    #[error("Failed to spawn async task")]
    TaskSpawnFailed(#[source] tokio_with_wasm::task::JoinError),

    #[cfg(not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )))]
    #[error("Failed to spawn async task")]
    TaskSpawnFailed(#[source] tokio::task::JoinError),

    // JWT claims flattening
    #[error("Failed to flatten JWT claims: {message}")]
    JwtClaimsFlattenFailed { message: String },

    // Policy content decode
    #[error("Failed to decode base64 policy content")]
    DecodePolicyContentFailed(#[source] base64::DecodeError),

    #[error("Invalid attestation service header name")]
    InvalidAttestationServiceHeaderName(#[source] reqwest::header::InvalidHeaderName),

    #[error("Invalid attestation service header value")]
    InvalidAttestationServiceHeaderValue(#[source] reqwest::header::InvalidHeaderValue),

    #[error("Unsupported hash-alg-id: {0}")]
    DiceUnsupportedHashAlgo(crate::cert::dice::cbor::HashAlgoIanaId),

    #[error("Calculate hash failed")]
    CalculateHashFailed,

    #[error("Failed to parse PEM certificate")]
    ParsePemCertError(#[source] pkcs8::der::Error),

    #[error("Failed to parse DER certificate")]
    ParseDerCertError(#[source] pkcs8::der::Error),

    #[error("Certificate verify signature failed")]
    CertVerifySignatureFailed(#[source] signature::Error),

    #[error("Failed to convert RSA public key from SPKI")]
    RsaPublicKeyConversionFailed(#[source] pkcs8::spki::Error),

    #[error("Failed to convert P256 public key from SPKI")]
    P256PublicKeyConversionFailed(#[source] pkcs8::spki::Error),

    #[error("Certificate issuer does not match")]
    CertIssuerMismatch,

    #[error("Could not get cert signature")]
    CertSignatureNotFound,

    #[error("Certificate extract extension failed")]
    CertExtractExtensionFailed,

    #[error("Certificate verify public key hash failed")]
    CertVerifyPublicKeyHashFailed,

    #[error("Unsupported rsa modulus bit length {0}")]
    UnsupportedRsaBitLen(usize),

    #[error("Failed to parse private key from pkcs8 pem format")]
    FromPkcs8PemFailed(#[source] pkcs8::Error),

    #[error("DER encoding/decoding error")]
    DerError(#[source] pkcs8::der::Error),

    #[error("SPKI error")]
    SpkiError(#[source] pkcs8::spki::Error),

    #[error("Unknown signature algo: {0}")]
    UnknownSignatureAlgo(pkcs8::ObjectIdentifier),

    // JSON serialization/deserialization errors (specific scenarios)
    #[error("Failed to serialize claims to JSON")]
    SerializeClaimsToJsonFailed(#[source] serde_json::Error),

    #[error("Failed to deserialize evidence from JSON")]
    DeserializeEvidenceFromJsonFailed(#[source] serde_json::Error),

    #[error("Failed to parse JWT claims")]
    ParseJwtClaimsFailed(#[source] serde_json::Error),

    #[error("Failed to serialize provenance")]
    SerializeProvenanceFailed(#[source] serde_json::Error),

    #[error("Failed to serialize SLSA reference value list")]
    SerializeSlsaReferenceValueListFailed(#[source] serde_json::Error),

    #[error("Failed to parse runtime data JSON")]
    ParseRuntimeDataJsonFailed(#[source] serde_json::Error),

    #[error("Failed to parse evidence from bytes")]
    ParseEvidenceFromBytesFailed(#[source] serde_json::Error),

    #[error("Failed to parse challenge response")]
    ParseChallengeResponseFailed(#[source] serde_json::Error),

    #[error("Failed to parse additional evidence JSON")]
    ParseAdditionalEvidenceJsonFailed(#[source] serde_json::Error),

    #[error("Failed to serialize canonical JSON")]
    SerializeCanonicalJsonFailed(#[source] serde_json::Error),

    #[error("Failed to serialize JSON")]
    SerializeJsonFailed(#[source] serde_json::Error),

    // ITA-specific errors
    #[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
    #[error("ITA HTTP request to `{endpoint}` failed: {source}")]
    ItaHttpRequestFailed {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },

    #[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
    #[error(
        "ITA HTTP response error from `{endpoint}`: status={status_code}, body={response_body}"
    )]
    ItaHttpResponseError {
        endpoint: String,
        status_code: u16,
        response_body: String,
    },

    #[cfg(feature = "verifier-ita")]
    #[error("ITA JWT verification failed: {0}")]
    ItaVerifyTokenFailed(#[source] jsonwebtoken::errors::Error),

    #[cfg(any(feature = "attester-ita", feature = "verifier-ita"))]
    #[error("ITA error: {0}")]
    ItaError(String),

    #[error("Incompatible types: {detail}")]
    IncompatibleTypes { detail: String },
}
