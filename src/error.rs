use serde::{Deserialize, Serialize};
use std::conver::Infallible;
use thiserror::{Error, ErrorKind};
use war::{http::StatusCode, Rejection, Reply};

pub enum Error {
    #[error("Wrong Credentials")]
    WrongCredentialError,
    #[error("JWT Token Not Valid")]
    JWTTokenError,
    #[error("JWT Token Creation Error")]
    JWTTokenCreationError,
    #[error("No Auth Header")]
    NoAuthHeaderError,
    #[error("Invalid Auth Header")]
    InvalidAuthHeaderError,
    #[error("No Permission")]
    NoPermissionError,
}
