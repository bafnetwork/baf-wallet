use argonautica::{Hasher, Verifier};
use http::StatusCode;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response};
use rocksdb::{Options, DB};
use secrecy::{Secret, SecretVec};
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use uuid::Uuid;
/// RocksDB stores only 2 mappings:
/// Email -> UserAccount
/// NearAccountID -> PrivKey

struct KeyPair {
    priv_key: SecretVec<u8>,
    pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Web2AuthRecord<'a> {
    password_hash: &'a str,
    id: u128,
}

struct Account<'a> {
    email: &'a str,
    near_account_id: Option<String>,
}

#[derive(Deserialize)]
struct SignupArgs<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct LoginArgs<'a> {
    email: &'a str,
    password: &'a str,
}

fn get_jwt_secret<'a>() -> Secret<&'a [u8]> {
    match std::env::var("JWT_SECRET") {
        Ok(secret) => Secret::new(secret.as_bytes()),
        Err(_) => panic!("JWT_SECRET environment variable not set!"),
    }
}

fn get_hasher_secret<'a>() -> Secret<&'a [u8]> {
    match std::env::var("HASHER_SECRET") {
        Ok(secret) => Secret::new(secret.as_bytes()),
        Err(_) => panic!("HASHER_SECRET environment variable not set!"),
    }
}

fn bad_request(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Bad Request"));
    *res.status_mut() = StatusCode::BAD_REQUEST;
    return res;
}

fn internal_server_error(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Internal Server Error"));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    return res;
}

/// Handler for all incoming RPC's. matches on the RPC's method and route and executes the
/// corresponding RPC
async fn handler<'a>(
    req: Request<Body>,
    db: Arc<DB>,
    hasher_secret: Secret<&'a [u8]>,
    jwt_secret: Secret<&'a [u8]>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/rpc") => {
            let body = hyper::body::to_bytes(req.into_body()).await?;
            let rpc: JsonRPC = match serde_json::from_slice(body.as_ref()) {
                Ok(json_rpc) => json_rpc,
                Err(e) => {
                    return Ok(bad_request(Some(e.into())));
                }
            };

            println!("method: {:#?}, id: {:#?}", rpc.method, rpc.id);

            match *&rpc.method {
                Some("createBafAccount") => {}
                Some("createNearAccount") => {}
                Some("signTx") => {}
                None => {
                    return Ok(bad_request(None));
                }
            }
        }
        (&Method::POST, "/login") => {
            let body = hyper::Body::to_bytes(req.into_body()).await?;
            let args: LoginArgs = match serde_json::from_slice(body.as_ref()) {
                Ok(args) => args,
                Err(e) => return Ok(bad_request(Some(e.into()))),
            };

            tokio::task::block_in_place(move || match db.get(args.email.as_bytes()) {
                Ok(Some(record_bytes)) => {
                    let mut verifier = Verifier::default();
                    let record: Web2AuthRecord = match serde_json::from_slice(record_bytes) {
                        Ok(record) => record,
                        Err(e) => return Ok(internal_server_error(Some(e.into()))),
                    };
                    match verifier
                        .with_hash(record.password_hash)
                        .with_password(args.password)
                        .with_secret_key(hasher_secret.reveal_secret())
                        .verify()
                    {
                        Ok(true) => {
                            // TODO: create a JWT containing record.id, a nonce (will need to import an RNG for this) and probably some other stuff
                            // TODO: return a response containing the JWT
                        }
                        Ok(false) => {
                            // TODO: return response with 404 not found
                        }
                        Err(e) => {
                            // TODO: print the error and return response with 505 internal server error
                        }
                    }
                }
                Ok(None) => {
                    // TODO return response with 404 not found
                }
                Err(e) => {
                    // TODO: print the error and return response with 505 internal server error
                }
            })
        }
        (&Method::POST, "/signup") => {
            let body = hyper::body::to_bytes(req.into_body()).await?;
            let args: SignupArgs = match serde_json::from_slice(body.as_ref()) {
                Ok(args) => args,
                Err(e) => return Ok(bad_request(Some(e.into()))),
            };

            tokio::task::block_in_place(move || {
                let mut hasher = Hasher::default();
                let password_hash = match hasher
                    .with_password(args.password)
                    .with_secret_key(hasher_secret.reveal_secret())
                    .hash()
                {
                    Ok(hashed) => hashed,
                    Err(e) => return Ok(internal_server_error(Some(e.into()))),
                };
                let record = Web2AuthRecord {
                    password_hash: password_hash,
                    id: Uuid::new_v4().as_u128(),
                };
                match db.put(args.email.as_bytes(), serde_json::to_vec(record).as_ref()) {
                    Ok(res) => {
                        let mut res = Response::new(Body::from("Created"));
                        *res.status_mut() = StatusCode::CREATED;
                        Ok(res)
                    }
                    Err(e) => return Ok(internal_server_error(Some(e.into()))),
                }
            })
        }
        _ => Ok(Response::new(Body::from(
            "Try POSTing data to /rpc such as: `curl localhost:3000/rpc -XPOST -d 'hello world'`",
        ))),
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct JsonRPC {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    id: i64, // for now, enforce ID to be a number
}

fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // start rocksdb, get a handle to it, and wrap it in an Arc so multiple threads can use it
    let path = std::env::var("ROCKSDB_STORAGE_PATH")
        .expect("ROCKSDB_STORAGE_PATH environment variable not set!");

    let db = Arc::new(DB::open_default(path).unwrap());

    // start the tokio runtime, start hyper inside it, and then block until the server dies
    {
        let db = Arc::clone(&db);
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let db = Arc::clone(&db);

            // A `Service` is needed for every connection, so this "service maker"
            // takes a connection and spits out an async function to handle the request
            let service_maker = make_service_fn(move |_conn| {
                let db = Arc::clone(&db);

                async move {
                    let db = Arc::clone(&db);
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let db = Arc::clone(&db);
                        let jwt_secret = get_jwt_secret();
                        let hasher_secret = get_hasher_secret();
                        handler(req, db, jwt_secret, hasher_secret)
                    }))
                }
            });

            let server = Server::bind(&addr).serve(service_maker);

            // Run this server for... forever!
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        });
    }

    // DB will automatically be closed when it gets dropped
}
