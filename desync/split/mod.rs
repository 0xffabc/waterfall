use crate::core::strategy::Strategy;
use crate::desync::strategy_core::{SplitPacket, StrategyExecutor};
use std::io::Write;

pub struct Split;

impl SplitPacket for Split {
    fn get_split_packet(
        packet_buffer: &[u8],
        strategy: Strategy,
        sni_data: &(u32, u32),
    ) -> Vec<Vec<u8>> {
        use crate::desync::utils::utils;

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

impl StrategyExecutor for Split {
    fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        mut socket: &'_ std::net::TcpStream,
    ) {
        if send_data.len() > 1 {
            let _ = socket.write_all(&send_data[0]);

            *current_data = send_data[1].clone();
        }
    }
}
