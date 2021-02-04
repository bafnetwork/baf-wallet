use crate::error::UserFacingError;
use anyhow::anyhow;
use http::StatusCode;
use hyper::header::HeaderValue;
use hyper::{Body, HeaderMap, Request, Response};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rocksdb::DB;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::pwhash::argon2id13;
use std::{any, sync::Arc};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
struct AuthPayload {
    user_id: Uuid,
}

/// value stored in rocksdb. corresponding key is an email.
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

/// handler for requests to the `/signup` endpoint
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

/// handler for requests to the `/login` endpoint
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
                let auth_payload = AuthPayload { user_id: record.id };
                let token = encode(
                    &Header::default(),
                    &auth_payload,
                    &EncodingKey::from_secret(jwt_secret.expose_secret()),
                )
                .map_err(|e| {
                    UserFacingError::InternalServerError(anyhow!(
                        "Error with validating your password!"
                    ))
                })?;

                let mut res = Response::new(Body::from(token));
                *res.status_mut() = StatusCode::OK;
                return Ok(res);
            } else {
                return Err(UserFacingError::AuthenticationFailed(anyhow!(
                    "Password or email are incorrect!"
                )));
            }
        } else {
            return Err(UserFacingError::AuthenticationFailed(anyhow!(
                "Password or email are incorrect!"
            )));
        }
    })
    .await
    .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::req;
    use crate::test_util::TestServer;
    use crate::util::JsonRpcResult;
    use crate::web2::*;
    use hyper::{client::HttpConnector, Client};
    use serde_json::json;
    use tokio::sync::oneshot;

    async fn signup(
        client: &Client<HttpConnector>,
        email: &str,
        password: &str,
        addr: SocketAddr,
    ) -> Response<Body> {
        let request = req!(
            json!({
               "email": email,
               "password": password,
            }),
            addr,
            "/signup"
        );
        let res = client.request(request).await.unwrap();
        return res;
    }

    async fn login(
        client: &Client<HttpConnector>,
        email: &str,
        password: &str,
        addr: SocketAddr,
    ) -> Response<Body> {
        let request = req!(
            json!({
               "email": email,
               "password": password,
            }),
            addr,
            "/login"
        );
        let res = client.request(request).await.unwrap();
        return res;
    }

    /// most basic possible test. More or less a sanity check.
    #[tokio::test]
    async fn test_signup_basic() {
        let (addr, test_server) = TestServer::new();
        let (stop_tx, join_handle) = test_server.start();

        tokio::task::yield_now().await;

        // create an account
        let client = Client::new();
        let res = signup(&client, "someemail@email.com", "Abcd123*", addr).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        stop_tx.send(()).ok();

        // send could fail in the event the server stops first
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

    /// most basic possible test. More or less a sanity check.
    #[tokio::test]
    async fn test_login_basic() {
        let (addr, test_server) = TestServer::new();
        let (stop_tx, join_handle) = test_server.start();

        tokio::task::yield_now().await;

        // create an account
        let client = Client::new();
        let email = "someemail@email.com";
        let pass = "Abcd123*";
        let signup_res = signup(&client, email, pass, addr).await;
        assert_eq!(signup_res.status(), StatusCode::CREATED);

        // test login
        let res = login(&client, email, pass, addr).await;
        assert_eq!(res.status(), StatusCode::OK);

        // test bad password
        let res_bad_email = login(&client, email, "fake news", addr).await;
        assert_eq!(res_bad_email.status(), StatusCode::UNAUTHORIZED);

        // test bad email
        let res_bad_email = login(&client, "fake@fake.co", pass, addr).await;
        assert_eq!(res_bad_email.status(), StatusCode::UNAUTHORIZED);

        stop_tx.send(()).ok();

        let test_server = join_handle.await.unwrap();
        test_server.destroy();
    }
}
