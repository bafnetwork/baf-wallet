use crate::error::UserFacingError;
use crate::near::{
    get_latest_block_hash, send_transaction_bytes, sign_and_serialize_transaction, view_account,
    Action, CreateAccountAction, ViewAccountArgs,
};
use crate::util::{JsonRpc, JsonRpcResult};
use crate::WALLET_ACCOUNT_ID;
use anyhow::anyhow;
use http::StatusCode;
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

struct CreateNearAccountArgs {
    account_id: String,
}

impl<'a> TryFrom<Value> for CreateNearAccountArgs {
    type Error = &'static str;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Object(obj) => {
                if let Some(Value::String(ref account_id)) = obj.get("account_id") {
                    Ok(CreateNearAccountArgs {
                        account_id: account_id.to_owned(),
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
    rpc: JsonRpc,
    db: Arc<DB>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Result<Response<Body>, UserFacingError> {
    let params = rpc.params.ok_or(UserFacingError::BadRequest(anyhow!(
        "rpc to create_near_account has no params!"
    )))?;
    let args = CreateNearAccountArgs::try_from(params)
        .map_err(|e| UserFacingError::BadRequest(anyhow!(e)))?;

    // check if the requested NEAR accountId exists
    let view_account_args = ViewAccountArgs::from(args.account_id.as_str());
    let view_account_res = view_account(view_account_args)
        .await
        .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;
    if let JsonRpcResult::Err(_e) = view_account_res {
        // TODO: actually check what the error is
        return Err(UserFacingError::NearAccountExists);
    };

    // create account

    let latest_block_hash = get_latest_block_hash()
        .await
        .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?;

    let tx_bytes = tokio::task::spawn_blocking(move || {
        let (pk, sk) = ed25519::gen_keypair();

        // encrypt keys
        let nonce = chacha20poly1305_ietf::Nonce::from_slice(
            randombytes(chacha20poly1305_ietf::NONCEBYTES).as_ref(),
        )
        .ok_or(UserFacingError::InternalServerError(anyhow!(
            "failed to generate nonce for record encryption"
        )))?;
        let enc = chacha20poly1305_ietf::seal(
            sk.as_ref(),
            Some(args.account_id.as_bytes()),
            &nonce,
            &encryption_key,
        );

        // put keys into database

        let record = NearKeyRecord {
            nonce: nonce,
            encrypted_key: enc.as_slice(),
        };
        let record_bytes = serde_json::to_vec(&record).map_err(|e| {
            UserFacingError::InternalServerError(anyhow!(format!("failed to serialize key: {}", e)))
        })?;

        db.put(args.account_id.as_str(), record_bytes)
            .map_err(|e| {
                UserFacingError::InternalServerError(anyhow!(format!(
                    "failed to PUT new key into database: {}",
                    e
                )))
            })?;

        // associate new keys with web2 auth record

        Ok(sign_and_serialize_transaction(
            vec![Action::CreateAccount(CreateAccountAction {})],
            &pk,
            &sk,
            &*WALLET_ACCOUNT_ID, // TODO: figure out what this should be
            &args.account_id,
            &latest_block_hash,
        ))
    })
    .await
    // ^ returns Result<Result<>>, outer is for joining the blocking task
    // inner is the result returned by the task
    .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))??;

    match send_transaction_bytes(tx_bytes)
        .await
        .map_err(|e| UserFacingError::InternalServerError(anyhow!(e)))?
    {
        JsonRpcResult::Ok(_response) => {
            // TODO there are probably other checks that need to happen here
            let mut res = Response::new(Body::from("created"));
            *res.status_mut() = StatusCode::CREATED;
            Ok(res)
        }
        // TODO handle this properly
        JsonRpcResult::Err(response) => {
            // TODO read the error
            Err(UserFacingError::InternalServerError(anyhow!(format!(
                "failed to create account on NEAR blockchain: {}",
                response.error
            ))))
        }
    }
}

pub async fn sign_transaction(
    rpc: JsonRpc,
    user_id: Uuid,
    db: Arc<DB>,
    encryption_key: chacha20poly1305_ietf::Key,
) -> Result<Response<Body>, UserFacingError> {
    // TODO: deserialize params, return bad request if it fails
    // TODO: get keys out of database
    // TODO: sign tx
    // TODO: send signed tx back to user
    unimplemented!()
}
