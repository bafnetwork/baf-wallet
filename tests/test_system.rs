use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::runtime::Builder;

lazy_static! {
    static ref counter: AtomicU32 = AtomicU16::new(0);
}

struct TestSystem {
    server_addr: SocketAddr,
}

fn start_server() -> SockedAddr {
    let count = counter.fetch_add(1, Ordering::SeqCst);
    let addr = SocketAddr::from(([127, 0, 0, 1], 1000 + count));
    let path = format!("tests/{}", count);
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    std::thread::spawn(move || {
        wrapped_main(true, 10000 + count, path, rt);
    });
    addr
}
