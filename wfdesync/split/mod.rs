pub struct Split;

use crate::{strategy_core::StrategyExecutor, utils::utils};

impl SplitPacket for Split {
    fn get_split_packet(
        packet_buffer: &[u8],
        strategy: Strategy,
        sni_data: &(u32, u32),
    ) -> Vec<Vec<u8>> {
        let (sni_start, _sni_end) = sni_data;
        let middle: u64 = (strategy.base_index as u64)
            + if strategy.add_sni {
                *sni_start as u64
            } else {
                0
            };

        if middle < packet_buffer.to_vec().len().try_into().unwrap() && middle > 0 {
            let packet_parts: Vec<Vec<u8>> = utils::slice_packet(packet_buffer.to_vec(), middle);

            return packet_parts;
        } else {
            return vec![packet_buffer.to_vec()];
        }
    }
}

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use wfconfig::strategy::Strategy;

use crate::strategy_core::SplitPacket;

impl StrategyExecutor for Split {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            socket.write_all(&send_data[0]).await?;

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}
