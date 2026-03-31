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
    #[error("Failed to create gRPC endpoint for AS address `{as_addr}`: {source}")]
    GrpcEndpointCreateFailed {
        as_addr: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("Failed to connect to gRPC AS address `{as_addr}`: {source}")]
    GrpcConnectFailed {
        as_addr: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("gRPC attestation evaluate failed (api_version: {0:?}): {1}")]
    AttestationServiceGrpcAttestationEvaluateFailed(GrpcAsVersion, #[source] tonic::Status),

    // AA ttrpc related errors
    #[error("Failed to get evidence from Attestation Agent: {0}")]
    GetEvidenceFromAAFailed(#[source] ttrpc::Error),

    #[error("Failed to get TEE type from Attestation Agent: {0}")]
    GetTeeTypeFromAAFailed(#[source] ttrpc::Error),

    #[error("Failed to connect to Attestation Agent ttrpc endpoint: {0}")]
    ConnectAttestationAgentTtrpcFailed(#[source] ttrpc::Error),

    #[error("Verify token failed: {0}")]
    CocoVerifyTokenFailed(#[source] crate::tee::coco::verifier::token::Error),

    // Built-in AS related
    // Certificate generation related errors
    #[error("Failed to generate certificate validity period: {0}")]
    CertValidityGenerationFailed(#[source] pkcs8::der::Error),

    #[error("Failed to parse certificate subject {0}: {1}")]
    CertSubjectParseFailed(String, #[source] pkcs8::der::Error),

    #[error("Failed to create SubjectPublicKeyInfo: {0}")]
    CertSpkiCreationFailed(#[source] pkcs8::spki::Error),

    #[error("Failed to build certificate: {0}")]
    CertBuildFailed(#[source] x509_cert::builder::Error),

    #[error("Failed to sign certificate: {0}")]
    CertSignFailed(#[source] x509_cert::builder::Error),

    #[error("Failed to encode certificate: {0}")]
    CertEncodeFailed(#[source] pkcs8::der::Error),

    #[error("Failed to generate CA certificate: {0}")]
    CaCertGenerationFailed(#[source] rcgen::Error),

    #[error("Failed to generate AS certificate: {0}")]
    AsCertGenerationFailed(#[source] rcgen::Error),

    #[error("Failed to create builtin attestation service working directory: {0}")]
    BuilinAttestationServiceCreateWorkDirFailed(#[source] std::io::Error),

    #[error("Failed to write AS private key to {path}: {source}")]
    WriteAsPrivateKeyFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write certificate chain to {path}: {source}")]
    WriteCertChainFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read policy file from {path}: {source}")]
    ReadPolicyFileFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read reference value file from {path}: {source}")]
    ReadReferenceValueFileFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Base64 decode failed: {0}")]
    Base64DecodeFailed(#[source] base64::DecodeError),

    // Reference value errors (specific scenarios)
    #[error("Failed to parse reference value payload from {path}: {source}")]
    ParseReferenceValuePayloadFailed {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to serialize reference value message: {0}")]
    SerializeReferenceValueMessageFailed(#[source] serde_json::Error),

    #[error("Failed to register sample reference value: {0}")]
    RegisterSampleReferenceValueFailed(#[source] anyhow::Error),

    #[error("Failed to set SLSA reference value list: {0}")]
    SetSlsaReferenceValueListFailed(#[source] anyhow::Error),

    // RSA key generation
    #[error("RSA key generation failed: {0}")]
    RsaKeyGenerationFailed(#[source] rsa::Error),

    // CBOR serialization/deserialization
    #[error("CBOR serialization failed: {0}")]
    CborSerializationFailed(#[source] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR deserialization failed: {0}")]
    CborDeserializationFailed(#[source] ciborium::de::Error<std::io::Error>),

    // UTF-8 conversion
    #[error("Invalid UTF-8 sequence in string: {0}")]
    InvalidUtf8(#[source] std::string::FromUtf8Error),

    #[error("Invalid UTF-8 sequence in byte slice: {0}")]
    InvalidUtf8Slice(#[source] std::str::Utf8Error),

    // TEE type
    #[error("Unknown TEE type: {tee_type}")]
    UnknownTeeType { tee_type: String },

    // gRPC metadata
    #[error("Invalid gRPC metadata key: {0}")]
    InvalidGrpcMetadataKey(#[source] tonic::metadata::errors::InvalidMetadataKey),

    #[error("Invalid gRPC metadata value: {0}")]
    InvalidGrpcMetadataValue(#[source] tonic::metadata::errors::InvalidMetadataValue),

    // Attestation service operations
    #[error("Failed to create attestation service: {0}")]
    AttestationServiceCreateFailed(#[source] attestation_service::ServiceError),

    #[error("Failed to set attestation policy: {0}")]
    AttestationServiceSetPolicyFailed(#[source] anyhow::Error),

    #[error("Failed to generate attestation challenge: {0}")]
    AttestationServiceGenerateChallengeFailed(#[source] anyhow::Error),

    #[error("Attestation evidence verification failed: {0}")]
    AttestationServiceVerifyFailed(#[source] anyhow::Error),

    // HTTP client building
    #[error("Failed to build HTTP client: {0}")]
    AttestationServiceHttpClientBuildFailed(#[source] reqwest::Error),

    #[error("Failed to send /challenge HTTP request to AS (api_version: {0:?}): {1}")]
    AttestationServiceChallengeHttpRequestSendFailed(RestfulAsApiVersion, #[source] reqwest::Error),

    #[error("Failed to send /attestation HTTP request to AS (api_version: {0:?}): {1}")]
    AttestationServiceAttestationHttpRequestSendFailed(
        RestfulAsApiVersion,
        #[source] reqwest::Error,
    ),

    #[error("Failed to read /challenge HTTP response from AS (api_version: {0:?}): {1}")]
    AttestationServiceChallengeHttpResponseReadFailed(
        RestfulAsApiVersion,
        #[source] reqwest::Error,
    ),

    #[error("Failed to read /attestation HTTP response from AS (api_version: {0:?}): {1}")]
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
    #[error("Failed to spawn async task: {0}")]
    TaskSpawnFailed(#[source] tokio::task::JoinError),

    // JWT claims flattening
    #[error("Failed to flatten JWT claims: {message}")]
    JwtClaimsFlattenFailed { message: String },

    // Policy content decode
    #[error("Failed to decode base64 policy content: {0}")]
    DecodePolicyContentFailed(#[source] base64::DecodeError),

    #[error("Invalid attestation service header name: {0}")]
    InvalidAttestationServiceHeaderName(#[source] reqwest::header::InvalidHeaderName),

    #[error("Invalid attestation service header value: {0}")]
    InvalidAttestationServiceHeaderValue(#[source] reqwest::header::InvalidHeaderValue),

    #[error("Unsupported hash-alg-id: {0}")]
    DiceUnsupportedHashAlgo(crate::cert::dice::cbor::HashAlgoIanaId),

    #[error("Calculate hash failed")]
    CalculateHashFailed,

    #[error("Failed to parse PEM certificate: {0}")]
    ParsePemCertError(#[source] pkcs8::der::Error),

    #[error("Failed to parse DER certificate: {0}")]
    ParseDerCertError(#[source] pkcs8::der::Error),

    #[error("Certificate verify signature failed: {0}")]
    CertVerifySignatureFailed(#[source] signature::Error),

    #[error("Failed to convert RSA public key from SPKI: {0}")]
    RsaPublicKeyConversionFailed(#[source] pkcs8::spki::Error),

    #[error("Failed to convert P256 public key from SPKI: {0}")]
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

    #[error("Failed to parse private key from pkcs8 pem format: {0}")]
    FromPkcs8PemFailed(#[source] pkcs8::Error),

    #[error("DER encoding/decoding error: {0}")]
    DerError(#[source] pkcs8::der::Error),

    #[error("SPKI error: {0}")]
    SpkiError(#[source] pkcs8::spki::Error),

    #[error("Unknown signature algo: {0}")]
    UnknownSignatureAlgo(pkcs8::ObjectIdentifier),

    // JSON serialization/deserialization errors (specific scenarios)
    #[error("Failed to serialize claims to JSON: {0}")]
    SerializeClaimsToJsonFailed(#[source] serde_json::Error),

    #[error("Failed to deserialize evidence from JSON: {0}")]
    DeserializeEvidenceFromJsonFailed(#[source] serde_json::Error),

    #[error("Failed to parse JWT claims: {0}")]
    ParseJwtClaimsFailed(#[source] serde_json::Error),

    #[error("Failed to serialize provenance: {0}")]
    SerializeProvenanceFailed(#[source] serde_json::Error),

    #[error("Failed to serialize SLSA reference value list: {0}")]
    SerializeSlsaReferenceValueListFailed(#[source] serde_json::Error),

    #[error("Failed to parse runtime data JSON: {0}")]
    ParseRuntimeDataJsonFailed(#[source] serde_json::Error),

    #[error("Failed to parse evidence from bytes: {0}")]
    ParseEvidenceFromBytesFailed(#[source] serde_json::Error),

    #[error("Failed to parse challenge response: {0}")]
    ParseChallengeResponseFailed(#[source] serde_json::Error),

    #[error("Failed to parse additional evidence JSON: {0}")]
    ParseAdditionalEvidenceJsonFailed(#[source] serde_json::Error),

    #[error("Failed to serialize canonical JSON: {0}")]
    SerializeCanonicalJsonFailed(#[source] serde_json::Error),
}
