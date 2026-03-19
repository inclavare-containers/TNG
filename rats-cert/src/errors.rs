use std::fmt::Display;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum ErrorKind {
    Unknown,

    UnsupportedTeeType,

    UnrecognizedEvidenceType,

    CocoConnectTtrpcFailed,

    CocoRequestAAFailed,

    CocoRequestASFailed,

    CocoVerifyTokenFailed,

    CocoParseTokenFailed,

    InvalidParameter,

    UnsupportedHashAlgo,

    CalculateHashFailed,

    GenCertError,

    ParseCertError,

    CertVerifySignatureFailed,

    CertExtractExtensionFailed,

    CertVerifyPublicKeyHashFailed,

    ParsePrivateKey,

    UnsupportedFeatures,
}

#[derive(Debug, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    msg: Option<String>,
}

#[allow(dead_code)]
impl Error {
    /// Create an Error with a unknown kind
    pub fn unknown() -> Self {
        Error::kind(ErrorKind::Unknown)
    }

    /// Create an Error with the specific kind
    pub fn kind(kind: ErrorKind) -> Self {
        Error { kind, msg: None }
    }

    /// Create an Error with the specific message
    pub fn msg<M>(msg: M) -> Self
    where
        M: Display,
    {
        Error::kind_with_msg(ErrorKind::Unknown, msg)
    }

    /// Create an Error with the specific kind and message
    pub fn kind_with_msg<M>(kind: ErrorKind, msg: M) -> Self
    where
        M: Display,
    {
        Error {
            kind,
            msg: Some(msg.to_string()),
        }
    }

    /// Set kind of self to a specific kind, and return this Error.
    pub fn with_kind(mut self, kind: ErrorKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set message of self to a specific message, and return this Error.
    pub fn with_msg<M>(mut self, msg: M) -> Self
    where
        M: Display,
    {
        self.msg = Some(msg.to_string());
        self
    }

    /// Get kind of this Error. If kind is not set, the default value is
    /// `Unknown`.
    pub fn get_kind(&self) -> ErrorKind {
        self.kind
    }

    /// Get a const ref msg of this Error. If msg is not set, None is returned.
    pub fn get_msg_ref(&self) -> &Option<String> {
        &self.msg
    }
}

// TODO: replace this with `impl<E: std::error::Error> From<E> for Error`，so that we can record source of our Error
impl<E: Display> From<E> for Error {
    fn from(error: E) -> Error {
        Error::kind_with_msg(ErrorKind::Unknown, error)
    }
}

pub trait IntoRatsError {
    fn into_rats_error(self) -> Error;
}

#[cfg(feature = "verifier-coco")]
impl IntoRatsError for tonic::Status {
    fn into_rats_error(self) -> Error {
        Error::kind_with_msg(
            ErrorKind::Unknown,
            format!("tonic status: {:?} msg: {}", self.code(), self.message()),
        )
    }
}

pub(crate) trait WithContext<T> {
    fn kind(self, kind: ErrorKind) -> Result<T>;

    fn context<C>(self, context: C) -> Result<T>
    where
        C: Display;

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Display,
        F: FnOnce() -> C;
}

#[allow(dead_code)]
impl<T, E> WithContext<T> for std::result::Result<T, E>
where
    Error: From<E>,
{
    fn kind(self, kind: ErrorKind) -> Result<T> {
        self.map_err(|error| Into::<Error>::into(error).with_kind(kind))
    }

    fn context<C>(self, context: C) -> Result<T>
    where
        C: Display,
    {
        self.map_err(|error| Into::<Error>::into(error))
            .map_err(|error| {
                if let Some(ref msg) = error.msg {
                    let new_msg = format!("{}: {}", context, msg);
                    error.with_msg(new_msg)
                } else {
                    error.with_msg(context)
                }
            })
    }

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Display,
        F: FnOnce() -> C,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e).context(f()),
        }
    }
}

// TODO: impl std::error::Error trait for our Error, so that we can provide `source` info.
/// This is a temporary workaround that makes it possible to convert our Error to an anyhow::Error. A better way is to impl std::error::Error trait for our Error.
impl From<Error> for anyhow::Error {
    fn from(value: Error) -> Self {
        anyhow::anyhow!(
            "rats-rs error kind {:?}: {}",
            value.kind,
            match &value.msg {
                Some(s) => s,
                None => "unknown reason",
            }
        )
    }
}
