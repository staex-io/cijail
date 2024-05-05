use std::fmt::Display;
use std::io::ErrorKind;

use http::uri::InvalidUriParts;
use libseccomp::error::SeccompError;
use thiserror::Error;

use crate::DnsNameError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("seccomp error: {0}")]
    Seccomp(#[from] SeccompError),
    #[error("os error: {0}")]
    Os(#[from] std::io::Error),
    #[error("dns name error: {0}")]
    DnsName(#[from] DnsNameError),
    #[error("bincode error: {0}")]
    BincodeEncode(bincode::error::EncodeError),
    #[error("bincode error: {0}")]
    BincodeDecode(bincode::error::DecodeError),
    #[error("base64 error: {0}")]
    Base64Decode(base64::DecodeError),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("http error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("fmt error: {0}")]
    Fmt(#[from] std::fmt::Error),
    #[error("uri error: {0}")]
    Uri(#[from] InvalidUriParts),
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("denied")]
    Deny,
}

impl Error {
    pub fn map(e: impl Display) -> Error {
        Self::other(e.to_string())
    }

    pub fn other(message: String) -> Error {
        Error::Os(std::io::Error::new(ErrorKind::Other, message))
    }
}

impl From<Error> for std::io::Error {
    fn from(other: Error) -> Self {
        match other {
            Error::Os(error) => error,
            other => std::io::Error::new(ErrorKind::Other, other.to_string()),
        }
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(other: bincode::error::EncodeError) -> Self {
        Self::map(other)
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(other: bincode::error::DecodeError) -> Self {
        Self::map(other)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(other: base64::DecodeError) -> Self {
        Self::map(other)
    }
}
