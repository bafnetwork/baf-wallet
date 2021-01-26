use crate::util::{bad_request, internal_server_error, not_found, ok};
use hyper::{Body, Response};
use log::error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserFacingError {
    #[error("ID does not exists")]
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
                ok()
            }
            Self::BafIdDNE | Self::IdExists | Self::NearAccountDNE | Self::NearAccountExists => {
                // TODO: add logging for these cases
                ok()
            }
        }
    }
}
