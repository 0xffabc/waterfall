use anyhow::Result;
use std::marker::PhantomData;
use tokio::net::TcpStream;

use crate::strategy_core::*;
use wfconfig::strategy::Strategy;

use crate::utils::utils::{send_duplicate, set_ttl_raw, write_oob_multi};

pub struct DisorderedOOB<T> {
    marker: PhantomData<T>,
}

pub struct Disoob;
pub struct Oob2;

impl<T> SplitPacket for DisorderedOOB<T> {
    fn get_split_packet(
        packet_buffer: &[u8],
        strategy: Strategy,
        sni_data: &(u32, u32),
    ) -> Vec<Vec<u8>> {
        use crate::utils::utils;

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

impl StrategyExecutor for Disoob {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let mut ax_part: Vec<u8> = send_data[0].clone();

            ax_part.push(
                wfconfig::parse_args()
                    .desync_options
                    .out_of_band_charid
                    .into(),
            );

            let _ = set_ttl_raw(&socket, 1);
            write_oob_multi(&socket, ax_part);
            let _ = set_ttl_raw(
                &socket,
                wfconfig::parse_args().desync_options.default_ttl.into(),
            );

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}

impl StrategyExecutor for Oob2 {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let mut ax_part: Vec<u8> = send_data[0].clone();

            ax_part.push(
                wfconfig::parse_args()
                    .desync_options
                    .out_of_band_charid
                    .into(),
            );

            let _ = set_ttl_raw(&socket, 1);
            write_oob_multi(&socket, ax_part);
            let _ = set_ttl_raw(
                &socket,
                wfconfig::parse_args().desync_options.default_ttl.into(),
            );

            let _ = send_duplicate(socket, send_data[1].clone());

            *current_data = vec![];
        }

        Ok(())
    }
}
