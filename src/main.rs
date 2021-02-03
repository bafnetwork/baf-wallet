use anyhow::anyhow;
use dotenv;
use futures::future::TryFutureExt;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response};
use lazy_static::lazy_static;
use rocksdb::DB;
use secrecy::{ExposeSecret,Secret, SecretVec};
use sodiumoxide::crypto::{
    aead::chacha20poly1305_ietf,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

mod error;
mod keystore;
mod near;
mod util;
mod web2;

#[cfg(test)]
mod test_util;

use error::UserFacingError;
use util::JsonRpc;

lazy_static! {
    pub static ref WALLET_ACCOUNT_ID: String = std::env::var("WALLET_ACCOUNT_ID")
        .expect("WALLET_ACCOUNT_ID environment variable not set!");
}

lazy_static! {
    pub static ref WALLET_ACCOUNT_KEYS: String = std::env::var("WALLET_ACCOUNT_KEYS")
        .expect("WALLET_ACCOUNT_KEYS environment variable not set!");
}

#[cfg(not(test))]
fn get_jwt_secret() -> SecretVec<u8> {
    match std::env::var("JWT_SECRET") {
        Ok(secret) => Secret::new(secret.into_bytes()),
        Err(_) => panic!("JWT_SECRET environment variable not set!"),
    }
}

#[cfg(test)]
fn get_jwt_secret() -> SecretVec<u8> {
    Secret::new("imasecret".to_owned().into_bytes())
}

#[cfg(not(test))]
fn get_encryption_key() -> chacha20poly1305_ietf::Key {
    match std::env::var("ENCRYPTION_KEY") {
        Ok(key) => {
            if key.len() != chacha20poly1305_ietf::KEYBYTES {
                panic!("Invalid ENCRYPTION_KEY environment variable: wrong length");
            }
            let key = Secret::new(key);
            chacha20poly1305_ietf::Key::from_slice(key.expose_secret().as_bytes())
                .expect("Invalid ENCRYPTION_KEY environment variable: failed to decode")
        }
        Err(_) => panic!("ENCRYPTION_KEY environment variable not set!"),
    }
}

#[cfg(test)]
fn get_encryption_key() -> chacha20poly1305_ietf::Key {
    let test_key: [u8; chacha20poly1305_ietf::KEYBYTES] = [7; chacha20poly1305_ietf::KEYBYTES];
    chacha20poly1305_ietf::Key::from_slice(&test_key).unwrap()
}

/// Handler for all incoming HTTP Requests. matches on the RPC's method and route and executes the
/// corresponding RPC
async fn handler(
    req: Request<Body>,
    db: Arc<DB>,
    jwt_secret: SecretVec<u8>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Result<Response<Body>, UserFacingError> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/rpc") => {
            // check auth headers
            let headers = req.headers();
            let auth_header_val = web2::get_auth_header(headers).ok_or(
                UserFacingError::AuthenticationFailed(anyhow!("unauthenticated request to /rpc")),
            )?;
            let user_id =
                tokio::task::spawn_blocking(move || web2::check_auth(auth_header_val, jwt_secret))
                    .await
                    .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;
            if let Some(user_id) = user_id {
                // deserialize RPC
                let body = hyper::body::to_bytes(req.into_body())
                    .await
                    .map_err(|e| UserFacingError::BadRequest(anyhow!(e)))?;
                let rpc: JsonRpc = serde_json::from_slice(body.as_ref())
                    .map_err(|e| UserFacingError::BadRequest(anyhow!(e)))?;

                // println!("method: {:#?}, id: {:#?}", rpc.method, rpc.id);

                // call handler corresponding to requested method
                match rpc.method.as_str() {
                    "createNearAccount" => {
                        keystore::create_near_account(rpc, db, encryption_key).await
                    }
                    "signTx" => keystore::sign_transaction(rpc, user_id, db, encryption_key).await,
                    _ => Err(UserFacingError::NotFound(anyhow!(
                        "request for non-existent method"
                    ))),
                }
            } else {
                Err(UserFacingError::NotFound(anyhow!(
                    "request to /rpc received from unauthenticated user"
                )))
            }
        }
        (&Method::POST, "/login") => web2::handle_login(req, db, jwt_secret).await,
        (&Method::POST, "/signup") => web2::handle_signup(req, db).await,
        _ => Err(UserFacingError::NotFound(anyhow!("route not found"))),
    }
}

async fn handler_unwrapper(
    req: Request<Body>,
    db: Arc<DB>,
    jwt_secret: SecretVec<u8>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Result<Response<Body>, Infallible> {
    Ok(handler(req, db, jwt_secret, encryption_key)
        .unwrap_or_else(|err: UserFacingError| err.to_res())
        .await)
}

/// wrapper function that allows the rocksdb instance, listen addresss, and and optional abort
/// signal to be injected at runtime. This makes it easier to write tests.
pub async fn main_inner(db: Arc<DB>, addr: &SocketAddr, stop_chan: Option<oneshot::Receiver<()>>) {
    sodiumoxide::init().expect("failed to initialize libsodium!");
    // A `Service` is needed for every connection, so this "service maker"
    // takes a connection and spits out an async function to handle the request
    let db = Arc::clone(&db);
    let service_maker = make_service_fn(move |_conn| {
        let db = Arc::clone(&db);

        async move {
            let db = Arc::clone(&db);
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let db = Arc::clone(&db);
                let jwt_secret = get_jwt_secret();
                let encryption_key = get_encryption_key();
                handler_unwrapper(req, db, jwt_secret, encryption_key)
            }))
        }
    });

    // hyper calls the "service maker" for each new connection
    let server = Server::bind(addr).serve(service_maker);

    // if stop_chan is Some, shutdown the server when receive "stop" signal over the channel
    let exit_status = match stop_chan {
        Some(stop) => {
            let server = server.with_graceful_shutdown(async {
                stop.await.ok();
            });
            server.await
        }
        None => server.await,
    };

    if let Err(e) = exit_status {
        eprintln!("server error: {}", e);
    }
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    // start rocksdb, get a handle to it, and wrap it in an Arc so multiple threads can use it

    let path = std::env::var("ROCKSDB_STORAGE_PATH")
        .expect("ROCKSDB_STORAGE_PATH environment variable not set!");

    let db = Arc::new(DB::open_default(&path).unwrap());

    let rt = Runtime::new().unwrap();

    rt.block_on(main_inner(Arc::clone(&db), &addr, None))

    // DB will automatically be closed when it gets dropped
}
