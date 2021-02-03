use crate::util::{JsonRpc, JsonRpcResult};
use anyhow::{anyhow, Error};
use base58;
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
use substring::Substring;
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt};

#[path = "./error.rs"]
mod error;
use error::UserFacingError;

/// Near wallet credentials
#[derive(Debug, Serialize, Deserialize)]
struct WalletCredentials {
    account_id: String,
    private_key: String,
    public_key: String,
}

/// Get the wallet's public and private key from a credentials file
async fn get_wallet_keys(
    cred_path: String,
) -> Result<(ed25519::PublicKey, ed25519::SecretKey), UserFacingError> {
    let mut f = File::open(cred_path)
        .await
        .map_err(|e| UserFacingError::WalletAccountKeyReadFail(anyhow!(e)))?;
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer)
        .await
        .map_err(|e| UserFacingError::WalletAccountKeyReadFail(anyhow!(e)))?;

    let wallet_creds: WalletCredentials = serde_json::from_slice(&buffer)
        .map_err(|e| UserFacingError::WalletAccountKeyReadFail(anyhow!(e)))?;

    let remove_prefix = |key: String| key.substring("ed25519:".len(), key.len()).to_string();

    let pub_trimmed = remove_prefix(wallet_creds.public_key);
    let secret_trimmed = remove_prefix(wallet_creds.private_key);

    let from_b58 = |v: String| {
        base58::FromBase58::from_base58(&v[..]).map_err(|_| {
            UserFacingError::WalletAccountKeyReadFail(anyhow!(
                "Failed to convert a key from base64!"
            ))
        })
    };

    let pub_vec = from_b58(pub_trimmed)?;
    let sec_vec = from_b58(secret_trimmed)?;
    let pub_key = ed25519::PublicKey::from_slice(&(pub_vec)).ok_or(
        UserFacingError::WalletAccountKeyReadFail(anyhow!("Failed to load the public key!")),
    )?;
    let secret_key = ed25519::SecretKey::from_slice(&sec_vec).ok_or(
        UserFacingError::WalletAccountKeyReadFail(anyhow!("Failed to load the secret key!")),
    )?;
    Ok((pub_key, secret_key))
}

/// args for NEAR's [`viewAccount` JSON-RPC endpoint](https://docs.near.org/docs/api/rpc#view-account)
#[derive(Serialize)]
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

/// calls NEAR's [`viewAccount` JSON-RPC endpoint](https://docs.near.org/docs/api/rpc#view-account)
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

/// Sign and serialize transaction
/// signer_id and receiver_id are near account id's
/// block_hash is a base-64 encoded string of the hash of the block atop which this transaction is
/// supposed to go.
pub fn sign_and_serialize_transaction(
    actions: Vec<Action>,
    pk: &ed25519::PublicKey,
    sk: &ed25519::SecretKey,
    signer_id: &str,
    receiver_id: &str,
    block_hash: &str,
) -> Bytes {
    let nonce_bytes = randombytes(8);
    let nonce: u64 = LittleEndian::read_u64(nonce_bytes.as_ref());
    let tx = Transaction {
        signer_id: signer_id.to_owned(),
        public_key: TxPubKey {
            // 0 corresponds to ed25519
            // see https://github.com/near/nearcore/blob/38d83a801b16ed3a9318716b077dc47d9ea8bc43/core/crypto/src/signature.rs#L20
            key_type: 0,
            data: pk.as_ref(),
        },
        nonce: nonce,
        receiver_id: receiver_id.to_owned(),
        block_hash: block_hash.to_owned(),
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
        .map_err(|e| anyhow!(e))?;
    let client = Client::new();
    let res = client.request(req).await.map_err(|e| anyhow!(e))?;
    let body = hyper::body::to_bytes(res.into_body())
        .await
        .map_err(|e| anyhow!(e))?;
    Ok(serde_json::from_slice::<JsonRpcResult>(body.as_ref()).map_err(|e| anyhow!(e))?)
}

/// parameters for "block" RPC
/// see https://docs.near.org/docs/api/rpc#block for more information
#[derive(Serialize, Deserialize)]
pub enum BlockArgs<'a> {
    Finality(&'a str),
    BlockId(u32),
    BlockHash(&'a str),
}

impl<'a> Into<JsonRpc> for BlockArgs<'a> {
    fn into(self) -> JsonRpc {
        let mut map = Map::new();
        match self {
            Self::Finality(finality) => {
                map.insert("finality".to_owned(), Value::String(finality.to_owned()));
                JsonRpc {
                    jsonrpc: "2.0".to_owned(),
                    method: "block".to_owned(),
                    params: Some(Value::Object(map)),
                    id: "dontcare".to_owned(),
                }
            }
            Self::BlockId(block_id) => {
                map.insert("block_id".to_owned(), Value::Number(block_id.into()));
                JsonRpc {
                    jsonrpc: "2.0".to_owned(),
                    method: "block".to_owned(),
                    params: Some(Value::Object(map)),
                    id: "dontcare".to_owned(),
                }
            }
            Self::BlockHash(block_hash) => {
                map.insert("block_id".to_owned(), Value::String(block_hash.to_owned()));
                JsonRpc {
                    jsonrpc: "2.0".to_owned(),
                    method: "block".to_owned(),
                    params: Some(Value::Object(map)),
                    id: "dontcare".to_owned(),
                }
            }
        }
    }
}

pub async fn get_latest_block_hash() -> Result<String, Error> {
    let rpc: JsonRpc = BlockArgs::Finality("final").into();
    let rpc_bytes = serde_json::to_vec(&rpc).map_err(|e| anyhow!(e))?;

    let req = Request::builder()
        .method(Method::POST)
        .uri("https:://rpc.testnet.near.org")
        .header("content-type", "application/json")
        .body(Body::from(rpc_bytes))
        .map_err(|e| anyhow!(e))?;
    let client = Client::new();

    let res = client.request(req).await.map_err(|e| anyhow!(e))?;
    let body = hyper::body::to_bytes(res.into_body())
        .await
        .map_err(|e| anyhow!(e))?;

    // TODO: make this less fugly
    match serde_json::from_slice::<JsonRpcResult>(body.as_ref()).map_err(|e| anyhow!(e))? {
        JsonRpcResult::Ok(response) => match response.result {
            Value::Object(obj) => match obj.get("header") {
                Some(&Value::Object(ref obj)) => match obj.get("hash") {
                    Some(&Value::String(ref hash)) => Ok(hash.to_owned()),
                    _ => Err(anyhow!(
                        "response to 'block' rpc does not have string field 'result.header.hash'"
                    )),
                },
                _ => Err(anyhow!(
                    "response to 'block' rpc does not have object field 'result.header'"
                )),
            },
            _ => Err(anyhow!(
                "response to 'block' rpc does not have object field 'result'"
            )),
        },
        JsonRpcResult::Err(response) => Err(anyhow!(
            serde_json::to_string_pretty(&response.error).map_err(|e| anyhow!(e))?
        )),
    }
}

/// NEAR JSON-RPC's [`SignedTransction`](https://github.com/near/near-api-js/blob/ca817850ff2faad426483835c779b32a84f5c979/src/transaction.ts#L144) type
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct SignedTransaction<'a, 'b> {
    #[serde(borrow)]
    transaction: Transaction<'a>,
    signature: &'b [u8],
}

/// NEAR JSON-RPC's [`Transction`](https://github.com/near/near-api-js/blob/ca817850ff2faad426483835c779b32a84f5c979/src/transaction.ts#L148) type
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct Transaction<'a> {
    signer_id: String,
    #[serde(borrow)]
    public_key: TxPubKey<'a>,
    nonce: u64,
    receiver_id: String,
    block_hash: String,
    actions: Vec<Action>,
}

/// NEAR JSON-RPC's [`PublicKey`](https://github.com/near/near-api-js/blob/ca817850ff2faad426483835c779b32a84f5c979/src/transaction.ts#L144) type
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct TxPubKey<'a> {
    key_type: u8,
    data: &'a [u8],
}

/// NEAR JSON-RPC's [`Action`](https://github.com/near/near-api-js/blob/ca817850ff2faad426483835c779b32a84f5c979/src/transaction.ts#L144) type
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub enum Action {
    CreateAccount(CreateAccountAction),
    // add more as actions as we need them
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize)]
pub struct CreateAccountAction;

#[cfg(test)]
mod tests {
    use super::get_wallet_keys;
    use sodiumoxide::crypto::sign::ed25519::{PublicKey};

    #[tokio::test]
    async fn test_get_wallet_keys() {
        let (pub_key, sec_key) = get_wallet_keys("test-env/baf-wallet.testnet.json".to_string())
            .await
            .unwrap();
        assert_eq!(
            pub_key,
            PublicKey([
                167, 220, 246, 228, 140, 246, 159, 72, 177, 251, 215, 94, 128, 85, 186, 104, 26,
                110, 108, 111, 120, 78, 24, 198, 12, 117, 190, 199, 91, 9, 112, 159
            ])
        );
        assert_eq!(sec_key.as_ref().len(), 64);
    }
}
