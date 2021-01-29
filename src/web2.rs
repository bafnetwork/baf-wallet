use crate::error::UserFacingError;
use anyhow::anyhow;
use http::StatusCode;
use hyper::header::HeaderValue;
use hyper::{Body, HeaderMap, Request, Response};
use jsonwebtoken::{decode, DecodingKey, Validation};
use rocksdb::DB;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::pwhash::argon2id13;
use std::sync::Arc;
use uuid::Uuid;

/// For web2, rocksdb stores the following:
/// email -> Web2AuthRecord

#[derive(Serialize, Deserialize, Debug)]
struct AuthPayload {
    user_id: Uuid,
}

#[derive(Serialize, Deserialize)]
struct Web2AuthRecord {
    // let sodiumoxide seroize password hashes
    password_hash: argon2id13::HashedPassword,
    id: Uuid,
    near_account_id: Option<String>,
}

#[derive(Deserialize)]
struct SignupArgs {
    email: SecretString,
    password: SecretString,
}

#[derive(Deserialize)]
struct LoginArgs {
    email: SecretString,
    password: SecretString,
}

pub fn get_auth_header(headers: &HeaderMap<HeaderValue>) -> Option<HeaderValue> {
    match headers.get("Authorization") {
        Some(val) => Some(val.clone()),
        None => None,
    }
}

/// check authorization header and cointained JWT token if it exists and return user's Web2AuthRecord ID
pub fn check_auth(val: HeaderValue, jwt_secret: SecretVec<u8>) -> Option<Uuid> {
    let val = match val.to_str() {
        Ok(val) => val,
        Err(e) => {
            eprintln!("invalid non-ASCII header value for `Authorization`: {}", e);
            return None;
        }
    };

    let bearer = "Bearer ";
    if val.len() < bearer.len() && bearer != &val[0..bearer.len()] {
        None
    } else {
        let token = &val[bearer.len()..];
        let validation = Validation::default();
        let decoding_key = DecodingKey::from_secret(jwt_secret.expose_secret().as_ref());
        match decode::<AuthPayload>(token, &decoding_key, &validation) {
            Ok(auth) => Some(auth.claims.user_id),
            Err(e) => {
                eprintln!("failed to decode JWT: {}", e);
                None
            }
        }
    }
}

pub async fn handle_signup(
    req: Request<Body>,
    db: Arc<DB>,
) -> Result<Response<Body>, UserFacingError> {
    let body = hyper::body::to_bytes(req.into_body())
        .await
        .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;

    tokio::task::spawn_blocking(move || {
        let args: SignupArgs = serde_json::from_slice(body.as_ref())
            .map_err(|e| UserFacingError::BadRequest(anyhow!(e)))?;
        let password_hash = argon2id13::pwhash(
            args.password.expose_secret().as_bytes(),
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .map_err(|_| UserFacingError::InternalServerError(anyhow!("failed to hash password")))?;

        let record = Web2AuthRecord {
            password_hash: password_hash,
            id: Uuid::new_v4(),
            near_account_id: None,
        };
        let serialized_record = serde_json::to_vec(&record)
            .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;

        db.put(args.email.expose_secret(), serialized_record)
            .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;

        let mut res = Response::new(Body::from("Created"));
        *res.status_mut() = StatusCode::CREATED;
        Ok(res)
    })
    .await
    .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?
}

pub async fn handle_login(
    req: Request<Body>,
    db: Arc<DB>,
    jwt_secret: SecretVec<u8>,
) -> Result<Response<Body>, UserFacingError> {
    let body = hyper::body::to_bytes(req.into_body())
        .await
        .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;

    tokio::task::spawn_blocking(move || {
        let args: LoginArgs = serde_json::from_slice(body.as_ref())
            .map_err(|e| UserFacingError::BadRequest(anyhow!(e)))?;
        if let Some(record_bytes) = db
            .get(args.email.expose_secret())
            .map_err(|e| UserFacingError::AuthenticationFailed(anyhow!(e)))?
        {
            let record: Web2AuthRecord = serde_json::from_slice(record_bytes.as_ref())
                .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;
            if argon2id13::pwhash_verify(
                &record.password_hash,
                args.password.expose_secret().as_bytes(),
            ) {
                // TODO: use jsonwebtoken
                // TODO: create a JWT containing record.id, a nonce (will need to import an RNG for this) and probably some other stuff
                // TODO: return a response containing the JWT
                unimplemented!()
            } else {
                // TODO: return response with 404 not found
                unimplemented!()
            }
        } else {
            unimplemented!()
        }
    })
    .await
    .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?
}

#[cfg(test)]
mod tests {
    use crate::req;
    use crate::test_util::TestServer;
    use crate::util::JsonRpcResult;
    use crate::web2::*;
    use hyper::Client;
    use serde_json::json;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_signup_basic() {
        let (addr, test_server) = TestServer::new();
        let (stop_tx, join_handle) = test_server.start();

        tokio::task::yield_now().await;

        let client = Client::new();

        // create an account

        let request = req!(
            json!({
               "email": "someone@gmail.com",
               "password": "password",
            }),
            addr,
            "/signup"
        );

        let res = client.request(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::CREATED);

        // send could fail in the event the server stops first
        stop_tx.send(()).ok();
        let test_server = join_handle.await.unwrap();

        // check db's record
        let record = test_server.db.get("someone@gmail.com".as_bytes()).unwrap();

        assert!(record.is_some());

        let record = record.unwrap();
        let record: Web2AuthRecord = serde_json::from_slice(record.as_slice())
            .expect("db record is not a valid Web2AuthRecord");
        assert!(record.near_account_id.is_none());

        test_server.destroy();
    }
}
