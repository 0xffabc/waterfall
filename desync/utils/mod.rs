pub mod doh;
pub mod filter;
pub mod ip;
pub mod random;
pub mod sni;

pub mod utils {
    use crate::core;
    use anyhow::Result;
    use std::io;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    #[cfg(unix)]
    pub fn set_ttl_raw(stream: &TcpStream, ttl: u32) -> io::Result<()> {
        use libc;
        use libc::{IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_HOPS, IP_TTL};
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();

        unsafe {
            libc::setsockopt(
                fd,
                IPPROTO_IP,
                IP_TTL,
                &ttl as *const _ as *const libc::c_void,
                std::mem::size_of_val(&ttl) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_UNICAST_HOPS,
                &ttl as *const _ as *const libc::c_void,
                std::mem::size_of_val(&ttl) as libc::socklen_t,
            );
        };

        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn set_ttl_raw(stream: &TcpStream, ttl: u32) -> io::Result<()> {
        use winapi::shared::ws2def::{IPPROTO_IP, IPPROTO_IPV6};
        use winapi::shared::ws2ipdef::{IPV6_UNICAST_HOPS, IP_TTL};
        use winapi::um::winsock2::setsockopt;

        use std::os::windows::io::AsRawSocket;

        let socket = stream.as_raw_socket();

        unsafe {
            setsockopt(
                socket as _,
                IPPROTO_IP,
                IP_TTL,
                &ttl as *const _ as *const i8,
                std::mem::size_of_val(&ttl) as i32,
            );
            setsockopt(
                socket as _,
                IPPROTO_IPV6.try_into().unwrap(),
                IPV6_UNICAST_HOPS,
                &ttl as *const _ as *const i8,
                std::mem::size_of_val(&ttl) as i32,
            );
        };

        Ok(())
    }

    pub async fn send_duplicate(socket: &mut TcpStream, packet: Vec<u8>) -> Result<()> {
        let conf = core::parse_args();

        set_ttl_raw(&socket, 1)?;
        socket.write_all(&packet.as_slice()).await?;
        set_ttl_raw(&socket, conf.desync_options.default_ttl.into())?;

        Ok(())
    }

    #[cfg(unix)]
    pub fn send_drop(socket: &TcpStream, data: Vec<u8>) {
        let conf = core::parse_args();
        let _ = set_ttl_raw(&socket, conf.fake_packet_options.fake_packet_ttl.into());

        if cfg!(unix) {
            use libc::{send, MSG_OOB};
            use std::os::unix::io::AsRawFd;

            let fd = socket.as_raw_fd();

            let _ = unsafe {
                send(
                    fd,
                    (&data.as_slice()).as_ptr() as *const _,
                    1,
                    if conf.fake_packet_options.fake_as_oob {
                        MSG_OOB
                    } else {
                        0
                    },
                );
            };
        }

        let _ = set_ttl_raw(&socket, conf.desync_options.default_ttl.into());
    }

    #[cfg(windows)]
    pub fn send_drop(socket: &TcpStream, data: Vec<u8>) {
        let conf = core::parse_args();
        let _ = set_ttl_raw(&socket, conf.fake_packet_options.fake_packet_ttl.into());

        use std::os::windows::io::{AsRawSocket, RawSocket};
        use winapi::um::winsock2::{send, MSG_OOB};

        let rs: RawSocket = socket.as_raw_socket();

        let _ = unsafe {
            send(
                rs.try_into().unwrap(),
                (&data.as_slice()).as_ptr() as *const _,
                1,
                if conf.fake_packet_options.fake_as_oob {
                    MSG_OOB
                } else {
                    0
                },
            );
        };

        let _ = set_ttl_raw(&socket, conf.desync_options.default_ttl.into());
    }

    pub fn slice_packet(source: Vec<u8>, index: u64) -> Vec<Vec<u8>> {
        let mut current_index: u64 = 0;

        let mut alpha: Vec<u8> = Vec::new();
        let mut beta: Vec<u8> = Vec::new();

        for byte in source {
            if current_index >= index {
                alpha.push(byte);
            } else {
                beta.push(byte);
            }

            current_index += 1;
        }

        vec![beta, alpha]
    }

    #[cfg(unix)]
    pub fn write_oob_multi(socket: &TcpStream, oob_data: Vec<u8>) {
        use libc::{send, MSG_OOB};
        use std::os::unix::io::AsRawFd;

        let data1 = oob_data.as_slice();
        let oob_len = oob_data.len();

        let fd = socket.as_raw_fd();

        let _ = unsafe {
            send(
                fd,
                data1.as_ptr() as *const _,
                oob_len.try_into().unwrap(),
                MSG_OOB,
            );
        };
    }

    #[cfg(target_os = "windows")]
    pub fn write_oob_multi(socket: &TcpStream, oob_data: Vec<u8>) {
        use std::os::windows::io::{AsRawSocket, RawSocket};
        use winapi::um::winsock2::{send, MSG_OOB};

        let data1 = oob_data.as_slice();
        let oob_len = oob_data.len();

        let rs: RawSocket = socket.as_raw_socket();

        let _ = unsafe {
            send(
                rs.try_into().unwrap(),
                data1.as_ptr() as *const _,
                oob_len.try_into().unwrap(),
                MSG_OOB,
            );
        };
    }

    #[cfg(unix)]
    pub fn disable_sack(socket: &TcpStream) {
        use libc::setsockopt;
        use std::os::unix::io::AsRawFd;

        let fd = socket.as_raw_fd();

        let filter: [libc::sock_filter; 7] = [
            libc::sock_filter {
                code: 0x30,
                jt: 0,
                jf: 0,
                k: 0x0000000c,
            },
            libc::sock_filter {
                code: 0x74,
                jt: 0,
                jf: 0,
                k: 0x00000004,
            },
            libc::sock_filter {
                code: 0x35,
                jt: 3,
                jf: 0,
                k: 0x0000000b,
            },
            libc::sock_filter {
                code: 0x30,
                jt: 0,
                jf: 0,
                k: 0x00000022,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: 0x00000005,
            },
            libc::sock_filter {
                code: 0x6,
                jt: 0,
                jf: 0,
                k: 0x00000000,
            },
            libc::sock_filter {
                code: 0x6,
                jt: 0,
                jf: 0,
                k: 0x00040000,
            },
        ];

        let bpf = libc::sock_fprog {
            len: filter.len() as libc::c_ushort,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        let _ = unsafe {
            setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &bpf as *const _ as *const libc::c_void,
                std::mem::size_of_val(&bpf) as libc::socklen_t,
            )
        };
    }

    #[cfg(windows)]
    pub fn disable_sack(_socket: &TcpStream) {
        unsafe {
            std::arch::asm!("nop");
        }

        warn!("disable_sack compiles to a `nop` instruction on windows. Please set registry key `HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters SackOpts=REG_DWORD(0)`");
    }
}
