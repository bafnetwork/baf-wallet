use anyhow::anyhow;
use futures::future::TryFutureExt;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response};
use rocksdb::DB;
use secrecy::{ExposeSecret, Secret, SecretVec};
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;

mod error;
mod keystore;
mod near;
mod util;
mod web2;

use error::UserFacingError;
use util::JsonRpc;

fn get_jwt_secret() -> SecretVec<u8> {
    match std::env::var("JWT_SECRET") {
        Ok(secret) => Secret::new(secret.into_bytes()),
        Err(_) => panic!("JWT_SECRET environment variable not set!"),
    }
}

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

/// Handler for all incoming RPC's. matches on the RPC's method and route and executes the
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
            let user_id = tokio::task::block_in_place(|| web2::check_auth(headers, jwt_secret));
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
                        keystore::create_near_account(rpc, user_id, db, encryption_key).await
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
        _ => Ok(Response::new(Body::from(
            "Try POSTing data to /rpc such as: `curl localhost:3000/rpc -XPOST -d 'hello world'`",
        ))),
    }
}

async fn handler_wrapper(
    req: Request<Body>,
    db: Arc<DB>,
    jwt_secret: SecretVec<u8>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Response<Body> {
    handler(req, db, jwt_secret, encryption_key)
        .unwrap_or_else(|err: UserFacingError| err.to_res())
        .await
}

async fn main_inner(db: Arc<DB>, addr: SocketAddr) {
    let addr_ref = &addr;

    // A `Service` is needed for every connection, so this "service maker"
    // takes a connection and spits out an async function to handle the request
    let db = Arc::clone(&db);
    let service_maker = make_service_fn(move |_conn| {
        let db = Arc::clone(&db);

        async move {
            let db = Arc::clone(&db);
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let db = Arc::clone(&db);
                let jwt_secret = get_jwt_secret();
                let encryption_key = get_encryption_key();
                handler(req, db, jwt_secret, encryption_key)
            }))
        }
    });

    // hyper calls the "service maker" for each new connection
    let server = Server::bind(&addr).serve(service_maker);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

fn wrapped_main(destroy_db_at_end: bool, port: u16, rocksdb_path: &str, rt: Runtime) {
    env_logger::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    // start rocksdb, get a handle to it, and wrap it in an Arc so multiple threads can use it

    let db = Arc::new(DB::open_default(rocksdb_path).unwrap());

    sodiumoxide::init().expect("failed to initialize libsodium!");

    // start the tokio runtime, start hyper inside it, and then block until the server dies
    {
        let db = Arc::clone(&db);
        rt.block_on(main_inner(db, addr));
    }

    // DB will automatically be closed when it gets dropped. We can also optionally destroy it (i.e, wipe the data).
    if destroy_db_at_end {
        let _ = DB::destroy(&rocksdb::Options::default(), rocksdb_path);
    }
}

fn main() {
    let path = std::env::var("ROCKSDB_STORAGE_PATH")
        .expect("ROCKSDB_STORAGE_PATH environment variable not set!");
    wrapped_main(false, 3000, &path, Runtime::new().unwrap())
}
