use std::net::IpAddr;

use crate::desync::utils::doh::DOHResolver;

#[derive(Debug, Clone)]
pub struct IpParser<'a> {
    pub host_raw: Vec<u8>,
    pub host_unprocessed: &'a [u8],
    pub port: u16,
    pub dest_addr_type: u8,
    pub is_udp: bool,
}

pub struct IpUtils();

impl<'a> IpParser<'a> {
    #[allow(mismatched_lifetime_syntaxes)]
    pub fn parse<'b>(buffer: &'b [u8]) -> IpParser {
        let dest_addr_type = buffer[3];
        let is_udp = buffer[1] == 0x03;

        match dest_addr_type {
            1 => {
                if buffer.len() < 10 {
                    return IpParser {
                        dest_addr_type,
                        host_raw: vec![0, 0, 0, 0],
                        host_unprocessed: &[0, 0, 0, 0],
                        port: 0,
                        is_udp,
                    };
                }
                IpParser {
                    dest_addr_type,
                    host_raw: buffer[4..8].to_vec(),
                    host_unprocessed: &buffer[4..8],
                    port: u16::from_be_bytes([buffer[8], buffer[9]]),
                    is_udp,
                }
            }
            3 => {
                let domain_length = buffer[4] as usize;

                if 6 + domain_length >= buffer.len() {
                    return IpParser {
                        dest_addr_type,
                        host_raw: vec![0, 0, 0, 0],
                        host_unprocessed: &[0, 0, 0, 0],
                        port: 0,
                        is_udp,
                    };
                }

                let domain = &buffer[5..5 + domain_length];
                let port =
                    u16::from_be_bytes([buffer[5 + domain_length], buffer[6 + domain_length]]);

                if let Ok(domain_str) = std::str::from_utf8(domain) {
                    if let Ok(ip_addr) = domain_str.parse::<IpAddr>() {
                        let ip_buffer = match ip_addr {
                            IpAddr::V4(ip) => ip.octets().to_vec(),
                            IpAddr::V6(ip) => ip.octets().to_vec(),
                        };

                        return IpParser {
                            dest_addr_type,
                            host_raw: ip_buffer,
                            host_unprocessed: &domain,
                            port,
                            is_udp,
                        };
                    }

                    if let Ok(ip) = DOHResolver::doh_resolver(domain_str.to_string()) {
                        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                            let ip_buffer = match ip_addr {
                                IpAddr::V4(ip) => ip.octets().to_vec(),
                                IpAddr::V6(ip) => ip.octets().to_vec(),
                            };

                            return IpParser {
                                dest_addr_type,
                                host_raw: ip_buffer,
                                host_unprocessed: &domain,
                                port,
                                is_udp,
                            };
                        }
                    }
                }

                IpParser {
                    dest_addr_type,
                    host_raw: vec![0, 0, 0, 0],
                    host_unprocessed: &domain,
                    port,
                    is_udp,
                }
            }
            4 => {
                if buffer.len() < 22 {
                    return IpParser {
                        dest_addr_type,
                        host_raw: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        host_unprocessed: &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        port: 0,
                        is_udp,
                    };
                }
                IpParser {
                    dest_addr_type,
                    host_raw: buffer[4..20].to_vec(),
                    host_unprocessed: &buffer[4..20],
                    port: u16::from_be_bytes([buffer[20], buffer[21]]),
                    is_udp,
                }
            }
            _ => IpParser {
                dest_addr_type,
                host_raw: [0, 0, 0, 0].to_vec(),
                host_unprocessed: &[0, 0, 0, 0],
                port: 0,
                is_udp,
            },
        }
    }
}

impl IpUtils {
    pub fn find_ip(data: Vec<u8>) -> Option<String> {
        String::from_utf8(data)
            .map_err(|_| ())
            .and_then(|text| {
                let mut digits = 0;
                let mut dots = 0;
                let mut start = None;

                for (i, c) in text.char_indices() {
                    match c {
                        '0'..='9' => {
                            if start.is_none() {
                                start = Some(i);
                            }
                            digits += 1;

                            if i == text.len() - 1 && dots == 3 && digits > 0 {
                                return Ok(text[start.unwrap()..=i].to_string());
                            }
                        }
                        '.' if digits > 0 => {
                            dots += 1;
                            digits = 0;

                            if dots > 3 {
                                digits = 0;
                                dots = 0;
                                start = None;
                            }
                        }
                        _ => {
                            if dots == 3 && digits > 0 {
                                return Ok(text[start.unwrap()..i].to_string());
                            }

                            digits = 0;
                            dots = 0;
                            start = None;
                        }
                    }
                }

                Err(())
            })
            .ok()
    }
}
