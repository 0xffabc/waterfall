use std::{net::SocketAddr, sync::LazyLock, time::Duration};

use tokio::sync::Mutex;

static MARKED_IPS: LazyLock<Mutex<Vec<SocketAddr>>> = LazyLock::new(|| Mutex::new(vec![]));

pub async fn add_marker(socket_addr: SocketAddr) {
    let mut lock = MARKED_IPS.lock().await;

    if !lock.contains(&socket_addr) {
        info!("{socket_addr} is 16-32kb blocked");

        lock.push(socket_addr);
    }
}

pub async fn is_16kb_blocked(socket_addr: SocketAddr) -> bool {
    let lock = MARKED_IPS.lock().await;

    lock.contains(&socket_addr)
}

pub fn start_cleanup_task() {
    tokio::spawn(async {
        info!("IP address cleanup task was started");

        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));

        loop {
            interval.tick().await;

            cleanup_marked_ips().await;
        }
    });
}

async fn cleanup_marked_ips() {
    let mut lock = MARKED_IPS.lock().await;

    let removed_count = lock.len();

    lock.clear();

    if removed_count > 0 {
        info!("Cleaned up {} IP addresses", removed_count);
    }
}
