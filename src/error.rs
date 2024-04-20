use std::fmt::Display;
use std::io::ErrorKind;

use libseccomp::error::SeccompError;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("seccomp error: {0}")]
    Seccomp(#[from] SeccompError),
    #[error("os error: {0}")]
    Os(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn map(e: impl Display) -> Error {
        Self::other(e.to_string())
    }

    pub(crate) fn other(message: String) -> Error {
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
