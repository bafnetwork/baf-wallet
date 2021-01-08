use http::StatusCode;
use hyper::{Body, Response};
use std::error::Error;

pub fn bad_request(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Bad Request"));
    *res.status_mut() = StatusCode::BAD_REQUEST;
    res
}

pub fn internal_server_error(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Internal Server Error"));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    res
}

pub fn not_found(e: Option<Box<dyn Error>>) -> Response<Body> {
    if let Some(e) = e {
        eprintln!("{}", e);
    }
    let mut res = Response::new(Body::from("Not Found"));
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}
