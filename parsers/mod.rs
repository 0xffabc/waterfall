
pub mod parsers {
  use std::net::{ToSocketAddrs, IpAddr};

  #[derive(Debug, Clone)]
  pub struct IpParser {
    pub host_raw: Vec<u8>,
    pub port: u16,
    pub dest_addr_type: u8
  }

  impl IpParser {
    pub fn parse(buffer: Vec<u8>) -> IpParser {
      let dest_addr_type: u8 = buffer[3];

      match dest_addr_type {
        1 => {
          IpParser {
            dest_addr_type,
            host_raw: vec![buffer[4], buffer[5], buffer[6], buffer[7]],
            port: u16::from_be_bytes([buffer[8], buffer[9]])
          }
        },
        3 => {
          let domain_length = buffer[4] as usize;
          let domain = &buffer[5..5 + domain_length];
          let domain_slice = std::str::from_utf8(domain).unwrap().to_socket_addrs().unwrap().next().unwrap();
          let ip_buffer: Vec<u8> = match domain_slice.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
          };

          IpParser {
            dest_addr_type,
            host_raw: ip_buffer,
            port: 443
          }
        },
        _ => {
          IpParser {
            dest_addr_type,
            host_raw: buffer[4..20].to_vec(),
            port: u16::from_be_bytes([buffer[20], buffer[21]])
          }
        }
      }
    }
  }
}