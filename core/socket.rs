use socket2::{Domain, Protocol, Socket, Type};
use std::thread;
use std::time::Duration;
use std::{
    io,
    net::{SocketAddr, TcpStream},
};

use crate::core::aux_config::{AuxConfig, SocketOptions};
use crate::core::parse_args;
use socket2_ext::{AddressBinding, BindDeviceOption};

pub struct SocketOps();

impl SocketOps {
    fn cutoff_options(so_clone: Socket, so_opt_cutoff: u64) {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(so_opt_cutoff));

            so_clone.set_recv_buffer_size(16653).unwrap();
            so_clone.set_send_buffer_size(16653).unwrap();
        });
    }

    pub fn connect_socket(addr: SocketAddr) -> io::Result<TcpStream> {
        let domain_type = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain_type, Type::STREAM, Some(Protocol::TCP))?;

        let interface = parse_args().bind_options.bind_iface;

        if &interface != "default" {
            socket.bind_to_device(BindDeviceOption::v4(&interface))?;
        }

        let SocketOptions {
            so_recv_size,
            so_send_size,
            so_opt_cutoff,
            ..
        } = parse_args().socket_options;

        socket.set_recv_buffer_size(so_recv_size)?;
        socket.set_send_buffer_size(so_send_size)?;
        socket.set_nodelay(true)?;
        socket.set_keepalive(true)?;

        Self::cutoff_options(socket.try_clone().unwrap(), so_opt_cutoff);

        if domain_type == Domain::IPV6 {
            socket.set_only_v6(false)?;
        }

        socket.connect(&addr.into())?;

        Ok(socket.into())
    }
}
