use crate::util::{bad_request, internal_server_error};
use http::StatusCode;
use hyper::header::HeaderValue;
use hyper::{Body, HeaderMap, Request, Response};
use jsonwebtoken::{decode, DecodingKey, Validation};
use rocksdb::DB;
use secrecy::{ExposeSecret, SecretVec};
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
struct Web2AuthRecord<'a> {
    password_hash: &'a [u8],
    id: Uuid,
}

struct Account<'a> {
    email: &'a str,
    near_account_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SignupArgs<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize, Deserialize)]
struct LoginArgs<'a> {
    email: &'a str,
    password: &'a str,
}

/// check authorization header and cointained JWT token if it exists and return user's Web2AuthRecord ID
pub fn check_auth(headers: &HeaderMap<HeaderValue>, jwt_secret: SecretVec<u8>) -> Option<Uuid> {
    match headers.get("Authorization") {
        Some(val) => {
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
        None => None,
    }
}

pub async fn handle_signup(
    req: Request<Body>,
    db: Arc<DB>,
) -> Result<Response<Body>, hyper::Error> {
    let body = hyper::body::to_bytes(req.into_body()).await?;
    let args: SignupArgs = match serde_json::from_slice(body.as_ref()) {
        Ok(args) => args,
        Err(e) => return Ok(bad_request(Some(e.into()))),
    };

    tokio::task::block_in_place(move || {
        let password_hash = match argon2id13::pwhash(
            args.password.as_bytes(),
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        ) {
            Ok(hashed) => hashed,
            Err(e) => return Ok(internal_server_error(None)),
        };
        let record = Web2AuthRecord {
            password_hash: password_hash.as_ref(),
            id: Uuid::new_v4(),
        };
        let serialized_record = match serde_json::to_vec(&record) {
            Ok(ser) => ser,
            Err(e) => return Ok(internal_server_error(Some(e.into()))),
        };
        match db.put(args.email.as_bytes(), serialized_record.as_slice()) {
            Ok(_) => {
                let mut res = Response::new(Body::from("Created"));
                *res.status_mut() = StatusCode::CREATED;
                Ok(res)
            }
            Err(e) => return Ok(internal_server_error(Some(e.into()))),
        }
    })
}

pub async fn handle_login(
    req: Request<Body>,
    db: Arc<DB>,
    jwt_secret: SecretVec<u8>,
) -> Result<Response<Body>, hyper::Error> {
    let body = hyper::body::to_bytes(req.into_body()).await?;
    let args: LoginArgs = match serde_json::from_slice(body.as_ref()) {
        Ok(args) => args,
        Err(e) => return Ok(bad_request(Some(e.into()))),
    };

    tokio::task::block_in_place(move || match db.get(args.email.as_bytes()) {
        Ok(Some(record_bytes)) => {
            let record: Web2AuthRecord = match serde_json::from_slice(record_bytes.as_ref()) {
                Ok(record) => record,
                Err(e) => return Ok(internal_server_error(Some(e.into()))),
            };
            if let Some(ref password_hash) =
                argon2id13::HashedPassword::from_slice(record.password_hash)
            {
                if argon2id13::pwhash_verify(password_hash, args.password.as_bytes()) {
                    // TODO: use jsonwebtoken
                    // TODO: create a JWT containing record.id, a nonce (will need to import an RNG for this) and probably some other stuff
                    // TODO: return a response containing the JWT
                    unimplemented!()
                } else {
                    // TODO: return response with 404 not found
                    unimplemented!()
                }
            }
            // TODO: return response with 404 not found
            unimplemented!()
        }
        Ok(None) => {
            // TODO return response with 404 not found
            unimplemented!()
        }
        Err(e) => {
            // TODO: print the error and return response with 505 internal server error
            unimplemented!()
        }
    })
}
