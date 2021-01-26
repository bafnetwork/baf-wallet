use crate::util::{JsonRpc, JsonRpcResult};
use anyhow::{anyhow, Error};
use borsh::BorshSerialize;
use byteorder::{ByteOrder, LittleEndian};
use bytes::Bytes;
use http::StatusCode;
use hyper::{Body, Client, Method, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes::randombytes;

#[derive(Serialize, Deserialize)]
pub struct ViewAccountArgs<'a> {
    request_type: &'a str,
    finality: &'a str,
    account_id: &'a str,
}

impl<'a> Into<JsonRpc> for ViewAccountArgs<'a> {
    fn into(self) -> JsonRpc {
        let mut map = Map::new();
        map.insert(
            "request_type".to_owned(),
            Value::String(self.request_type.to_owned()),
        );
        map.insert(
            "finality".to_owned(),
            Value::String(self.finality.to_owned()),
        );
        map.insert(
            "account_id".to_owned(),
            Value::String(self.account_id.to_owned()),
        );
        JsonRpc {
            jsonrpc: "2.0".to_owned(),
            method: "query".to_owned(),
            params: Some(Value::Object(map)),
            id: "dontcare".to_owned(),
        }
    }
}

impl<'a> From<&'a str> for ViewAccountArgs<'a> {
    fn from(account_id: &'a str) -> ViewAccountArgs<'a> {
        ViewAccountArgs {
            request_type: "query",
            finality: "optimistic",
            account_id: account_id,
        }
    }
}
pub async fn view_account<'a>(args: ViewAccountArgs<'a>) -> Result<JsonRpcResult, Error> {
    let view_account_bytes = serde_json::to_vec(&args).map_err(|e| anyhow!(e))?;

    // TODO: put uri into env variable
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://rpc.testnet.near.org")
        .header("content-type", "application/json")
        .body(Body::from(view_account_bytes))
        .map_err(|e| anyhow!(e))?;
    let client = Client::new();
    let res = client.request(req).await.map_err(|e| anyhow!(e))?;
    if res.status() != StatusCode::OK {
        return Err(anyhow!(
            "Status Code of response from ViewAccount RPC not OK!"
        ));
    }
    let res_body = hyper::body::to_bytes(res.into_body())
        .await
        .map_err(|e| anyhow!(e))?;
    Ok(serde_json::from_slice(res_body.as_ref()).map_err(|e| anyhow!(e))?)
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct SignedTransaction<'a, 'b> {
    #[serde(borrow)]
    transaction: Transaction<'a>,
    signature: &'b [u8],
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct Transaction<'a> {
    signer_id: &'a str,
    public_key: TxPubKey<'a>,
    nonce: u64,
    receiver_id: &'a str,
    block_hash: &'a [u8],
    actions: Vec<Action>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct TxPubKey<'a> {
    key_type: u8,
    data: &'a [u8],
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub enum Action {
    CreateAccount(CreateAccountAction),
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct CreateAccountAction;
pub fn sign_and_serialize_transaction<'a, 'b>(
    actions: Vec<Action>,
    pk: &ed25519::PublicKey,
    sk: &ed25519::SecretKey,
    signer_id: &'a str,
    receiver_id: &'b str,
) -> Bytes {
    let nonce_bytes = randombytes(8);
    let nonce: u64 = LittleEndian::read_u64(nonce_bytes.as_ref());
    let tx = Transaction {
        signer_id: signer_id.as_ref(),
        public_key: TxPubKey {
            key_type: 0, // TODO look up what this should be
            data: pk.as_ref(),
        },
        nonce: nonce,
        receiver_id: receiver_id,
        block_hash: 0, // TODO figure out what this should be
        actions: actions,
    };
    let borshed = tx
        .try_to_vec()
        .expect("failed to serialize tx for signing purposes");
    let hashed = sha256::hash(borshed.as_ref());
    let sig = ed25519::sign(hashed.as_ref(), sk);

    let signed_tx = SignedTransaction {
        transaction: tx,
        signature: sig.as_ref(),
    };

    serde_json::to_vec(&signed_tx)
        .expect("failed to serialize transaction")
        .into()
}

pub async fn send_transaction_bytes(tx_bytes: Bytes) -> Result<JsonRpcResult, Error> {
    // send RPC
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://rpc.testnet.near.org")
        .header("content-type", "application/json")
        .body(Body::from(tx_bytes))
        .unwrap();
    let client = Client::new();
    // TODO handle this properly
    let res = client.request(req).await.map_err(|e| anyhow!(e))?;
    // TODO handle this properly
    let body = hyper::body::to_bytes(res.into_body())
        .await
        .map_err(|e| anyhow!(e))?;
    // TODO handle this properly
    Ok(serde_json::from_slice::<JsonRpcResult>(body.as_ref()).map_err(|e| anyhow!(e))?)
}
