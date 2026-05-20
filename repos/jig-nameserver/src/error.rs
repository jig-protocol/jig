//! Error types for Jig Nameserver

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, NameServerError>;

#[derive(Debug, Error)]
pub enum NameServerError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for NameServerError {
    fn from(e: rusqlite::Error) -> Self {
        NameServerError::Storage(e.to_string())
    }
}

impl IntoResponse for NameServerError {
    fn into_response(self) -> Response {
        let status = match self {
            NameServerError::BadRequest(_) => StatusCode::BAD_REQUEST,
            NameServerError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            NameServerError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            NameServerError::NotFound(_) => StatusCode::NOT_FOUND,
            NameServerError::Crypto(_) => StatusCode::BAD_REQUEST,
            NameServerError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            NameServerError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
