use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response};
use rocksdb::{Options, DB};
use secrecy::SecretVec;
use serde::{Serialize, Deserialize};
use serde_json::value::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use http::StatusCode;

/// RocksDB stores only 2 mappings:
/// Email -> UserAccount
/// NearAccountID -> PrivKey

struct KeyPair {
    priv_key: SecretVec<u8>,
    pub_key: Vec<u8>,
}

struct UserAccount {
    id: u64,
    email: String,
    near_account_id: Option<String>,
    hashed_password: Vec<u8>,
}

/// Handler for all incoming RPC's. matches on the RPC's method and route and executes the
/// corresponding RPC
async fn handler(req: Request<Body>, _db: Arc<DB>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/rpc") => {
            let body = hyper::body::to_bytes(req.into_body()).await?;
            let rpc: JsonRPC = match serde_json::from_slice(body.as_ref()) {
                Ok(json_rpc) => json_rpc,
                Err(e) => {
                    eprintln!("{}", e);
                    let mut res = Response::new(Body::from("Bad Request"));
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                }
            };

            println!(
                "method: {:#?}, id: {:#?}",
                rpc.method, rpc.id
            );

            match rpc.params {
                Some(_params) => {
                    unimplemented!()
                }
                None => {
                    let mut res = Response::new(Body::from("Bad Request"));
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                }
            }
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
    id: i64 // for now, enforce ID to be a number
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
                        handler(req, db)
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
