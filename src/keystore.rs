use crate::util::{bad_request, internal_server_error, not_found};
use crate::JsonRPC;
use hyper::{Body, Response};
use hyper::{Client, Method, Request, Uri};
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use serde_json::map::Map;
use serde_json::value::Value;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes::randombytes;
use std::convert::TryFrom;
use std::convert::Into;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct NearKeyRecord<'a> {
    nonce: chacha20poly1305_ietf::Nonce,
    encrypted_key: &'a [u8],
}

struct CreateNearAccountArgs<'a> {
    account_id: &'a str,
}

impl<'a> TryFrom<Value> for CreateNearAccountArgs<'a> {
    type Error = &'static str;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Object(obj) => {
                if let Some(Value::String(ref account_id)) = obj.get("account_id") {
                    Ok(CreateNearAccountArgs {
                        account_id: account_id,
                    })
                } else {
                    Err("invalid JSON-RPC params for CreateNearAccount")
                }
            }
            _ => Err("invalid JSON-RPC params for CreateNearAccount"),
        }
    }
}

struct ViewAccountArgs<'a> {
    request_type: &'a str,
    finality: &'a str,
    account_id: &'a str,
}

impl<'a> Into<JsonRPC> for ViewAccountArgs<'a> {
    fn into(self) -> JsonRPC {
        let mut map = Map::new();
        map.insert("request_type", self.request_type);
        map.insert("finality", self.finality);
        map.insert("account_id", self.account_id);
        JsonRPC {
            jsonrpc: "2.0",
            method: "query",
            params: Some(Value::Object(map)),
            id: "dontcare",
        }
    }
}

impl<'a> From<&'a str> for ViewAccountArgs<'a> {
    fn from(account_id: &'a str) -> ViewAccountArgs<'a> {
        ViewAccountArgs {
            request_type: "query",
            finality: "optimistic"
            account_id: account_id,
        }
    }
}

pub async fn create_near_account(
    rpc: JsonRPC,
    user_id: Uuid,
    db: Arc<DB>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Result<Response<Body>, hyper::Error> {
    let args = match rpc.params {
        Some(params) => match CreateNearAccountArgs::try_from(params) {
            Ok(args) => args,
            Err(e) => return Ok(bad_request(Some(e.into()))),
        },
        None => {
            return Ok(bad_request(Some(
                "rpc to create_near_account has no params!".into(),
            )))
        }
    };

    let view_account_args = ViewAccountArgs::from(args.account_id);
    match serde_json::to_vec(&view_account_args) {
        Ok(view_account_bytes) => {
            // TODO: put uri into env variable
            let req = match Request::builder()
                .method(Method::POST)
                .uri("https://rpc.testnet.near.org")
                .header("content-type", "application/json")
                .body(Body::from(view_account_bytes)) {
                    Ok(req) => req,
                    Err(e) => return Ok(internal_server_error(Some(e.into())))
                };
            let client = Client::new();
            let res = client.request(req).await {
                Ok(res) => {
                    if res.status == StatusCode::OK {
                        res
                    } else {
                        return Ok(internal_server_error("response to ViewAccount not Ok!".into())),
                    }
                }
                Err(e) => return Ok(internal_server_error(Some(e.into())))
            }
            let res_body = match hyper::body::to_bytes(req.into_body()).await {
                Ok(res_body) => res_body,
                Err(e) => return Ok(internal_server_error(Some(e.into())))
            }
            // TODO deserialize RPC response, check to make sure account exists
            unimplemented!()
        }
        Err(e) => return Ok(internal_server_error(Some(e.into)))
    }
    // TODO: check if NEAR accountID exists
    let (_pk, mut sk) = ed25519::gen_keypair();

    let tx = tokio::task::block_in_place(move || {
        let nonce = match chacha20poly1305_ietf::Nonce::from_slice(
            randombytes(chacha20poly1305_ietf::NONCEBYTES).as_ref(),
        ) {
            Some(nonce) => nonce,
            None => return None,
        };
        let enc = chacha20poly1305_ietf::seal(
            sk.as_ref(),
            Some(args.account_id.as_bytes()),
            &nonce,
            &encryption_key,
        );
        let record = NearKeyRecord {
            nonce: nonce,
            encrypted_key: enc.as_slice(),
        };
        let record_bytes = match serde_json::to_vec(&record) {
            Ok(record_bytes) => record_bytes,
            Err(e) => {
                eprintln!("failed to deserialize key: {}", e);
                return None;
            }
        };

        match db.put(args.account_id, record_bytes.as_ref()) {
            Ok(_) => {
                // TODO: make and sign transaction to create account, return Some(tx)
                unimplemented!()
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
            unimplemented!()
        }
        None => Ok(internal_server_error(Some(
            "failed to create account on NEAR blockchain".into(),
        ))),
    }
}

pub async fn sign_tx(
    rpc: JsonRPC,
    user_id: Uuid,
    db: Arc<DB>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Result<Response<Body>, hyper::Error> {
    // TODO: deserialize params, return bad request if it fails
    // TODO: get keys out of database
    // TODO: sign tx
    // TODO: send signed tx back to user
    unimplemented!()
}
