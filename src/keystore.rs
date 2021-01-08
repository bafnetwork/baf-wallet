use crate::util::{bad_request, internal_server_error, not_found};
use crate::JsonRPC;
use hyper::{Body, Response};
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes::randombytes;
use std::convert::TryFrom;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct NearKeyRecord<'a> {
    nonce: chacha20poly1305_ietf::Nonce,
    encrypted_key: &'a [u8],
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
            Some(args.accountId.as_bytes()),
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

        match db.put(args.accountId, record_bytes.as_ref()) {
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
