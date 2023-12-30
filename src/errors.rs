//! Custom Error that Actix web automatically converts to a HTTP response.
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::fmt;

#[cfg(feature = "actix")]
use actix_web::{HttpResponse, error::ResponseError, http::StatusCode};


#[macro_export]
macro_rules! safe_eject {
    ($e:expr, $err_status:expr) => {
        $e.map_err(|x| CustomError::new(x.to_string(), $err_status))
    };
}


/// The status of the custom error.
/// 
/// # Fields
/// * `NotFound` - The request was not found.
/// * `Forbidden` - You are forbidden to access.
/// * `Unknown` - An unknown internal error occurred.
/// * `BadRequest` - The request was bad.
/// * `Conflict` - The request conflicted with the current state of the server.
#[derive(Error, Debug, Serialize, Deserialize, PartialEq)]
pub enum CustomErrorStatus {
    #[error("Requested file was not found")]
    NotFound,
    #[error("You are forbidden to access requested file.")]
    Forbidden,
    #[error("Unknown Internal Error")]
    Unknown,
    #[error("Bad Request")]
    BadRequest,
    #[error("Conflict")]
    Conflict,
    #[error("Unauthorized")]
    Unauthorized
}


/// The custom error that Actix web automatically converts to a HTTP response.
/// 
/// # Fields
/// * `message` - The message of the error.
/// * `status` - The status of the error.
#[derive(Serialize, Deserialize, Debug, Error)]
pub struct CustomError {
    pub message: String,
    pub status: CustomErrorStatus
}

impl CustomError {

    /// Constructs a new error.
    /// 
    /// # Arguments
    /// * `message` - The message of the error.
    /// * `status` - The status of the error.
    /// 
    /// # Returns
    /// * `CustomError` - The new error.
    pub fn new(message: String, status: CustomErrorStatus) -> CustomError {
        CustomError {
            message,
            status
        }
    }
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}


#[cfg(feature = "actix")]
impl ResponseError for CustomError {
    
    /// Yields the status code for the error.
    /// 
    /// # Returns
    /// * `StatusCode` - The status code for the error.
    fn status_code(&self) -> StatusCode {
        match self.status {
            CustomErrorStatus::NotFound  => StatusCode::NOT_FOUND,
            CustomErrorStatus::Forbidden => StatusCode::FORBIDDEN,
            CustomErrorStatus::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            CustomErrorStatus::BadRequest => StatusCode::BAD_REQUEST,
            CustomErrorStatus::Conflict => StatusCode::CONFLICT,
            CustomErrorStatus::Unauthorized => StatusCode::UNAUTHORIZED
        }
    }

    /// Constructs a HTTP response for the error.
    /// 
    /// # Returns
    /// * `HttpResponse` - The HTTP response for the error.
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        HttpResponse::build(status_code).json(self.message.clone())
    }
}
