use crate::main_inner;
use lazy_static::lazy_static;
use rocksdb::DB;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

lazy_static! {
    static ref COUNTER: AtomicU16 = AtomicU16::new(0);
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub db: Arc<DB>,
    pub db_path: String,
}

impl TestServer {
    pub fn new() -> (SocketAddr, Self) {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        let addr = SocketAddr::from(([127, 0, 0, 1], 9000 + count));
        let db_path = format!("testdb/{}", count);
        let db = Arc::new(DB::open_default(&db_path).unwrap());
        (addr.clone(), TestServer { addr, db, db_path })
    }

    pub fn destroy(self) {
        // wipe the test DB after we're done with it
        let _ = DB::destroy(&rocksdb::Options::default(), self.db_path);
    }

    /// panics if run outside the context of a tokio runtime
    pub fn start(self) -> (oneshot::Sender<()>, JoinHandle<Self>) {
        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        let join_handle = tokio::task::spawn(async move {
            main_inner(Arc::clone(&self.db), &self.addr, Some(stop_rx)).await;
            self
        });

        (stop_tx, join_handle)
    }
}

#[macro_export]
macro_rules! req {
    ($serializable:expr, $addr:expr, $route:expr) => {
        hyper::Request::builder()
            .uri(format!("http://{}:{}{}", $addr.ip(), $addr.port(), $route))
            .method(hyper::Method::POST)
            .header("content-type", "application/json")
            .body(hyper::Body::from(
                serde_json::to_string(&$serializable).unwrap(),
            ))
            .unwrap()
    };
}
