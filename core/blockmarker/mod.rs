use std::{net::SocketAddr, sync::LazyLock, time::Duration};

use tokio::sync::Mutex;

static MARKED_IPS: LazyLock<Mutex<Vec<SocketAddr>>> = LazyLock::new(|| Mutex::new(vec![]));

pub async fn add_marker(socket_addr: SocketAddr) {
    let mut lock = MARKED_IPS.lock().await;

    if !lock.contains(&socket_addr) {
        warn!(
            "Marking {:?} since a 16-32kb block has been detected",
            socket_addr
        );

        lock.push(socket_addr);
    }
}

pub async fn remove_marker(socket_addr: SocketAddr) {
    let mut lock = MARKED_IPS.lock().await;

    info!(
        "Unmarking {socket_addr:?} from 16-30kb block list, since a normalized connectivity was proven"
    );

    lock.retain(|v| v != &socket_addr);
}

pub async fn is_16kb_blocked(socket_addr: SocketAddr) -> bool {
    let lock = MARKED_IPS.lock().await;

    lock.contains(&socket_addr)
}

pub fn start_cleanup_task() {
    tokio::spawn(async {
        info!("IP address cleanup task was started");

        let mut interval = tokio::time::interval(Duration::from_secs(300));

        let mut derivative_val;

        loop {
            interval.tick().await;

            let mut lock = MARKED_IPS.lock().await;

            derivative_val = std::cmp::max(4, lock.len());

            lock.drain(0..derivative_val);

            info!("Cleaned up {derivative_val} IPs");
        }
    });
}
