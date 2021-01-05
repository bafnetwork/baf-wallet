use http::StatusCode;
use hyper::header::HeaderValue;
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, HeaderMap, Method, Request, Response};
use jsonwebtoken::{decode, encode, DecodingKey, Validation};
use rocksdb::DB;
use secrecy::{ExposeSecret, Secret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};
use serde_json::map::Map;
use serde_json::value::Value;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes::randombytes;
use std::convert::TryFrom;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use uuid::Uuid;
/// RocksDB stores only 2 mappings:
/// Email -> UserAccount
/// NearAccountID -> PrivKey

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct JsonRPC {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    id: i64, // for now, enforce ID to be a number
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthPayload {
    user_id: Uuid,
}

#[derive(Serialize, Deserialize)]
struct Web2AuthRecord<'a> {
    password_hash: &'a [u8],
    id: Uuid,
}

#[derive(Serialize, Deserialize)]
struct NearKeyRecord<'a> {
    nonce: chacha20poly1305_ietf::Nonce,
    encrypted_key: &'a [u8],
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

struct CreateNearAccountArgs<'a> {
    accountId: &'a str,
}

impl<'a> TryFrom<Value> for CreateNearAccountArgs<'a> {
    type Error = &'static str;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Object(obj) => {
                if let Some(Value::String(ref accountId)) = obj.get("accountId") {
                    Ok(CreateNearAccountArgs {
                        accountId: accountId,
                    })
                } else {
                    Err("invalid JSON-RPC params for CreateNearAccount")
                }
            }
            _ => Err("invalid JSON-RPC params for CreateNearAccount"),
        }
    }
}

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

fn bad_request(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Bad Request"));
    *res.status_mut() = StatusCode::BAD_REQUEST;
    res
}

fn internal_server_error(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Internal Server Error"));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    res
}

fn not_found(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Not Found"));
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

/// check authorization header and cointained JWT token if it exists and return user's Web2AuthRecord ID
fn check_auth(headers: &HeaderMap<HeaderValue>, jwt_secret: SecretVec<u8>) -> Option<Uuid> {
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

/// Handler for all incoming RPC's. matches on the RPC's method and route and executes the
/// corresponding RPC
async fn handler(
    req: Request<Body>,
    db: Arc<DB>,
    jwt_secret: SecretVec<u8>,
    encryption_key: chacha20poly1305_ietf::Key,
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
            let headers = req.headers();
            let user_id: Uuid =
                match tokio::task::block_in_place(|| check_auth(headers, &jwt_secret)) {
                    Some(user_id) => user_id,
                    None => not_found(None),
                };

            match *&rpc.method {
                "createNearAccount" => {
                    // TODO: deserialize params, return bad request if it fails
                    let args = match CreateNearAccountArgs::try_from(rpc.params) {
                        Ok(args) => args,
                        Err(e) => return Ok(bad_request(Some(e.into()))),
                    };
                    // TODO: check if NEAR accountID exists
                    let (_pk, mut sk) = ed25519::gen_keypair();

                    let tx = tokio::task::block_in_place(move || {
                        let nonce = match chacha20poly1305_ietf::Nonce::from_slice(randombytes(
                            chacha20poly1305_ietf::NONCEBYTES,
                        )) {
                            Some(nonce) => nonce,
                            None => return internal_server_error(None),
                        };
                        let enc = chacha20poly1305_ietf::seal(
                            sk,
                            Some(args.accountId),
                            &nonce,
                            encryption_key,
                        );
                        let record = NearKeyRecord {
                            nonce: nonce,
                            encrypted_key: enc.as_ref(),
                        };
                        let record_bytes = match serde_json::to_vec(record) {
                            Ok(record_bytes) => record_bytes,
                            Err(e) => {
                                eprintln!("failed to deserialize key: {}", e);
                                None
                            }
                        };

                        match db.put(args.accountId, record_bytes.as_ref()) {
                            Ok(_) => {
                                // TODO: make and sign transaction to create account, return Some(tx)
                            }
                            Err(e) => {
                                eprintln!("failed to PUT new key into database: {}", e);
                                None
                            }
                        }
                    });
                    match tx {
                        Some(tx) => {
                            // TODO: send tx, wait for response from NEAR blockchain, return response to client accordingly
                        }
                        None => internal_server_error(Some(
                            "failed to create account on NEAR blockchain".into(),
                        )),
                    }
                }
                "signTx" => {
                    // TODO: deserialize params, return bad request if it fails
                    // TODO: get keys out of database
                    // TODO: sign tx
                    // TODO: send signed tx back to user
                }
                _ => {
                    return Ok(bad_request(None));
                }
            }
        }
        (&Method::POST, "/login") => {
            let body = hyper::body::to_bytes(req.into_body()).await?;
            let args: LoginArgs = match serde_json::from_slice(body.as_ref()) {
                Ok(args) => args,
                Err(e) => return Ok(bad_request(Some(e.into()))),
            };

            tokio::task::block_in_place(move || match db.get(args.email.as_bytes()) {
                Ok(Some(record_bytes)) => {
                    let record: Web2AuthRecord = match serde_json::from_slice(record_bytes.as_ref())
                    {
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
                        } else {
                            // TODO: return response with 404 not found
                        }
                    }
                    // TODO: return response with 404 not found
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
                match db.put(args.email.as_bytes(), serialized_record.as_ref()) {
                    Ok(_) => {
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

fn wrapped_main(destroy_db_at_end: bool) {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let addr_ref = &addr;

    // start rocksdb, get a handle to it, and wrap it in an Arc so multiple threads can use it
    let path = std::env::var("ROCKSDB_STORAGE_PATH")
        .expect("ROCKSDB_STORAGE_PATH environment variable not set!");

    let db = Arc::new(DB::open_default(path).unwrap());

    sodiumoxide::init().expect("failed to initialize libsodium!");

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
                        let encryption_key = get_encryption_key();
                        handler(req, db, jwt_secret, encryption_key)
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

    // DB will automatically be closed when it gets dropped. We can also optionally destroy it (i.e, wipe the data).
    if destroy_db_at_end {
        let _ = DB::destroy(&rocksdb::Options::default(), path);
    }
}

fn main() {
    wrapped_main(false)
}
