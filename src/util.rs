use http::StatusCode;
use hyper::{Body, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// HTTP Response helpers
pub fn bad_request() -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::BAD_REQUEST;
    res
}

pub fn internal_server_error() -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    res
}

pub fn not_found() -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

pub fn invalid_input(msg: Option<String>) -> Response<Body> {
    let body = match msg {
        Some(msg) => Body::from(serde_json::to_string(&json!({ "error": msg })).unwrap()),
        None => Body::empty(),
    };
    let mut res = Response::new(body);
    *res.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
    res
}

pub fn ok() -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::OK;
    res
}

pub fn authentication_failed() -> Response<Body> {
    let mut res = Response::new(Body::from("Unauthorized"));
    *res.status_mut() = StatusCode::UNAUTHORIZED;
    res

}

/// JSON-RPC helper structs for serialization/deserialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpc {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcOk {
    pub jsonrpc: String,
    pub result: Value,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcErr {
    pub jsonrpc: String,
    pub error: Value,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JsonRpcResult {
    Ok(JsonRpcOk),
    Err(JsonRpcErr),
    // TODO: add notification type
}
