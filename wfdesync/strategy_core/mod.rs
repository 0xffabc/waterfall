use anyhow::Result;
use tokio::net::TcpStream;
use wfconfig::strategy::Strategy;

pub trait SplitPacket {
    fn get_split_packet(
        packet_buffer: &[u8],
        strategy: Strategy,
        sni_data: &(u32, u32),
    ) -> Vec<Vec<u8>>;
}

pub trait StrategyExecutor {
    #[allow(async_fn_in_trait)]
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut TcpStream,
    ) -> Result<()>;
}
