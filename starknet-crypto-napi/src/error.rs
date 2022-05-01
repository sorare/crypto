use starknet_crypto::{SignError, VerifyError};
use starknet_ff::FromHexError;
use std::fmt;

pub enum Error {
    FromHexError(FromHexError),
    SignError(SignError),
    VerifyError(VerifyError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FromHexError(err) => {
                write!(f, "{}", err)
            }
            Error::SignError(err) => {
                write!(f, "{}", err)
            }
            Error::VerifyError(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl From<Error> for napi::Error {
    fn from(error: Error) -> Self {
        napi::Error::from_reason(format!("{}", error))
    }
}

impl From<FromHexError> for Error {
    fn from(error: FromHexError) -> Self {
        Error::FromHexError(error)
    }
}

impl From<SignError> for Error {
    fn from(error: SignError) -> Self {
        Error::SignError(error)
    }
}

impl From<VerifyError> for Error {
    fn from(error: VerifyError) -> Self {
        Error::VerifyError(error)
    }
}
