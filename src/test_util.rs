use crate::main_inner;
use lazy_static::lazy_static;
use rocksdb::DB;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    static ref COUNTER: AtomicU16 = AtomicU16::new(0);
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub db: Arc<DB>,
    pub db_path: String,
}

impl TestServer {
    pub fn new(worker_threads: usize) -> (SocketAddr, Self) {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        let addr = SocketAddr::from(([127, 0, 0, 1], 9000 + count));
        let db_path = format!("tests/{}", count);
        let db = Arc::new(DB::open_default(&db_path).unwrap());
        (addr.clone(), TestServer { addr, db, db_path })
    }

    pub fn destroy(self) {
        // wipe the test DB after we're done with it
        let _ = DB::destroy(&rocksdb::Options::default(), self.db_path);
    }

    pub async fn start(self) -> Self {
        main_inner(Arc::clone(&self.db), &self.addr).await;
        self
    }
}

#[macro_export]
macro_rules! req {
    ($serializable:expr, $addr:expr) => {
        hyper::Request::builder()
            .uri(format!("http://{}:{}", $addr.ip(), $addr.port()))
            .method(hyper::Method::POST)
            .header("content-type", "application/json")
            .body(hyper::Body::from(
                serde_json::to_string(&$serializable).unwrap(),
            ))
            .unwrap()
    };
}
