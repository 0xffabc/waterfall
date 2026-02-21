use std::{net::SocketAddr, sync::LazyLock};

use tokio::sync::Mutex;

static MARKED_IPS: LazyLock<Mutex<Vec<SocketAddr>>> = LazyLock::new(|| Mutex::new(vec![]));

pub async fn add_marker(socket_addr: SocketAddr) {
    let mut lock = MARKED_IPS.lock().await;

    if !is_16kb_blocked(socket_addr).await {
        info!("{socket_addr} is 16-32kb blocked");

        lock.push(socket_addr);
    }
}

pub async fn is_16kb_blocked(socket_addr: SocketAddr) -> bool {
    let lock = MARKED_IPS.lock().await;

    lock.contains(&socket_addr)
}
