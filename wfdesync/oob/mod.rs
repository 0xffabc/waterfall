use anyhow::Result;
use wfconfig::strategy::Strategy;

use crate::{
    strategy_core::StrategyExecutor,
    utils::utils::{self, write_oob_multi},
};
use std::marker::PhantomData;

pub struct OobD<T> {
    _marker: PhantomData<T>,
}

impl<T> SplitPacket for OobD<T> {
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

pub struct Oob;
pub struct OobStream;

impl StrategyExecutor for Oob {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let mut ax_part: Vec<u8> = send_data[0].clone();

            ax_part.push(
                wfconfig::parse_args()
                    .desync_options
                    .out_of_band_charid
                    .into(),
            );

            write_oob_multi(&socket, ax_part);

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}

use tokio::io::AsyncWriteExt;

use crate::strategy_core::SplitPacket;

impl StrategyExecutor for OobStream {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let ax_part: Vec<u8> = send_data[0].clone();

            let _ = socket.write_all(&ax_part);

            let oob_part = wfconfig::parse_args()
                .socket_options
                .so_oob_streamhell_data
                .clone();

            for byte in oob_part.as_bytes() {
                write_oob_multi(&socket, vec![*byte]);
            }

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}
