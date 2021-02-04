use crate::util::{authentication_failed, bad_request, internal_server_error, not_found, ok};
use hyper::{Body, Response};
use log::error;
use thiserror::Error;

/// UserFacingError is a wrapper for all errors that occur in the wallet. They are 'user facing'
/// in the sense that the error messages defined using [`thiserror`](thiserror)'s `#[error(...)]`
/// macro are the only errors the user should ever see - the inner errors, *what actually happened*,
/// are logged in the "to_res" method below that consumes a `UserFacingError` and turns it into a
/// [`Response`](hyper::Response).
///
/// You can wrap any value of a type that implements the std library's [`Error`](std::error::Error)
/// in a `UserFacingError` via the [`anyhow`][anyhow] crate.
#[derive(Error, Debug)]
pub enum UserFacingError {
    #[error("ID does not exist")]
    BafIdDNE,

    #[error("ID alredy exists")]
    IdExists,

    #[error("near account does not exist")]
    NearAccountDNE,

    #[error("near account already exists")]
    NearAccountExists,

    #[error("authentication failed")]
    AuthenticationFailed(anyhow::Error),

    #[error("internal server error")]
    InternalServerError(anyhow::Error),

    #[error("bad request")]
    BadRequest(anyhow::Error),

    #[error("not found")]
    NotFound(anyhow::Error),

    #[error("failed to load wallet account keys")]
    WalletAccountKeyReadFail(anyhow::Error),
}

impl UserFacingError {
    pub fn to_res(self) -> Response<Body> {
        match self {
            Self::InternalServerError(err) => {
                error!("{}", err);
                internal_server_error()
            }
            Self::BadRequest(err) => {
                error!("{}", err);
                bad_request()
            }
            Self::NotFound(err) => {
                error!("{}", err);
                not_found()
            }
            Self::AuthenticationFailed(err) => {
                error!("{}", err);
                authentication_failed()
            }
            Self::WalletAccountKeyReadFail(err) => {
                error!("{}", err);
                internal_server_error()
            }

            Self::BafIdDNE | Self::IdExists | Self::NearAccountDNE | Self::NearAccountExists => {
                // TODO: add logging for these cases
                ok()
            }
        }
    }
}
