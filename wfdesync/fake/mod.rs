use std::marker::PhantomData;

use anyhow::Result;

use crate::{strategy_core::StrategyExecutor, utils::utils};

pub struct FakeD<T> {
    _marker: PhantomData<T>,
}

impl<T> FakeD<T> {
    pub fn get_fake_http(host: String) -> String {
        return format!(
            "GET / HTTP 1.1
Host: {:?}
Content-Type: text/html
Content-Length: 1
a",
            host
        )
        .replace("\"", "")
        .replace("\"", "");
    }

    pub fn get_fake_packet(mut packet: Vec<u8>) -> Vec<u8> {
        let conf = wfconfig::parse_args();

        if let Some(data) = conf.fake_packet_options.fake_packet_override_data {
            return data;
        } else if conf.fake_packet_options.fake_packet_send_http {
            let fake_http: String = Self::get_fake_http(conf.fake_packet_options.fake_packet_host);
            let bytes: Vec<u8> = Vec::from(fake_http.as_bytes());

            return bytes;
        } else {
            let (sni_start, sni_end) = Sni::parse_sni_index(packet.clone());
            let fake_sni: Vec<String> = String::from(conf.fake_packet_options.fake_packet_sni)
                .chars()
                .map(|ch| String::from(ch))
                .collect();
            let mut sni_offset: u32 = 0;

            for iter in sni_start..sni_end {
                if sni_start + sni_offset + 1 > packet.len().try_into().unwrap() {
                    break;
                }
                if iter + 1 > packet.len().try_into().unwrap() {
                    break;
                };
                if sni_offset + 1 > fake_sni.len().try_into().unwrap() {
                    break;
                };

                packet[iter as usize] = fake_sni[sni_offset as usize].as_bytes()[0];
                sni_offset += 1;
            }

            return packet.clone();
        }
    }
}

impl<T> SplitPacket for FakeD<T> {
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

pub struct Fake2Disorder;
pub struct FakeSurround;
pub struct FakeInsert;
pub struct Meltdown;
pub struct FakeMD;
pub struct Fake;

impl StrategyExecutor for Fake {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let _ = utils::send_duplicate(socket, send_data[0].clone());
            utils::send_drop(
                &socket,
                FakeD::<Fake>::get_fake_packet(
                    send_data[if wfconfig::parse_args()
                        .fake_packet_options
                        .fake_packet_reversed
                    {
                        0
                    } else {
                        1
                    }]
                    .clone(),
                ),
            );

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}

use tokio::io::AsyncWriteExt;
use wfconfig::strategy::Strategy;

use crate::{strategy_core::SplitPacket, utils::sni::Sni};

impl StrategyExecutor for FakeMD {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            socket.write_all(&send_data[0]).await?;

            utils::send_drop(
                &socket,
                FakeD::<FakeMD>::get_fake_packet(
                    send_data[if wfconfig::parse_args()
                        .fake_packet_options
                        .fake_packet_reversed
                    {
                        0
                    } else {
                        1
                    }]
                    .clone(),
                ),
            );

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}

impl StrategyExecutor for FakeInsert {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let _ = socket.write_all(&send_data[0]);

            utils::send_drop(
                &socket,
                FakeD::<FakeInsert>::get_fake_packet(send_data[1].clone()),
            );

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}

impl StrategyExecutor for Fake2Disorder {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            let _ = socket.write_all(&send_data[0]);

            utils::send_drop(
                &socket,
                FakeD::<Fake2Disorder>::get_fake_packet(send_data[1].clone()),
            );

            let _ = utils::send_duplicate(socket, send_data[1].clone());

            *current_data = vec![];
        }

        Ok(())
    }
}

impl StrategyExecutor for FakeSurround {
    async fn execute_strategy(
        send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        if send_data.len() > 1 {
            utils::send_drop(
                &socket,
                FakeD::<FakeSurround>::get_fake_packet(
                    send_data[if wfconfig::parse_args()
                        .fake_packet_options
                        .fake_packet_reversed
                    {
                        0
                    } else {
                        1
                    }]
                    .clone(),
                ),
            );

            let _ = socket.write_all(&send_data[0]);

            utils::send_drop(
                &socket,
                FakeD::<FakeSurround>::get_fake_packet(
                    send_data[if wfconfig::parse_args()
                        .fake_packet_options
                        .fake_packet_reversed
                    {
                        0
                    } else {
                        1
                    }]
                    .clone(),
                ),
            );

            *current_data = send_data[1].clone();
        }

        Ok(())
    }
}

impl StrategyExecutor for Meltdown {
    async fn execute_strategy(
        _send_data: Vec<Vec<u8>>,
        current_data: &mut Vec<u8>,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        let _ = utils::send_duplicate(socket, current_data.clone());

        *current_data = vec![];

        Ok(())
    }
}
