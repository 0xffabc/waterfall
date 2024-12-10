use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Clone)]
struct Config {
    split_sni: bool,
    split_certificate: bool,
    split_offset: u8,
    raw_socket_mss: u16,
        
    out_of_band_byte: u8,
    out_of_band: bool,
    
    disorder_corrupt_ttl: bool,
    disorder_fake_packet: bool,
    
    fake_default_ttl: u8,
    fake_bad_sequence_num: bool,
    fake_bad_sequence_increment: i16,
    fake_bad_md5_sign: bool,
    fake_packet_mss: u16,

    fake_generate_clienthello: bool,
    fake_generate_serverhello: bool,
    fake_generate_sack: bool,
    fake_generate_handshake: bool,
    fake_generate_certificate: bool,
    
    fake_packet_certificate: Vec<u8>,
    fake_packet_clienthello: Vec<u8>,
    fake_sni_clienthello: Vec<u8>,
    fake_certificate_common: Vec<u8>,
    fake_serverhello: Vec<u8>,
    fake_sack: Vec<u8>,
    fake_quic_initial: Vec<u8>,
    fake_udp_datagram: Vec<u8>,
    
    http_host_random_case: bool,
    http_host_spelling: String,
    http_domain_random_case: bool,
    
    autocorrupt_url: String,
    server_drop_if_autocorrupt: bool,
}

#[derive(Debug)]
struct PacketAbstraction {
    split_parts: Vec<Packet>,
    send_after_inbound: Vec<Packet>
}

#[derive(Debug, Clone)]
struct Packet {
    raw_body: Vec<u8>,
    time_to_live: u8,
    is_udp: bool,
    is_out_of_band: bool,
    synchronize_mss: u16
}

impl Packet {
    fn new(default_ttl: u8, is_udp: bool, is_out_of_band: bool) -> Packet {
        let packet: Packet = Packet {
            raw_body: vec![],
            time_to_live: default_ttl,
            is_udp, is_out_of_band,
            synchronize_mss: 1500
        };
        
        packet
    }
    
    fn push(&mut self, hex_byte: u8) -> u8 {
        self.raw_body.push(hex_byte);
        
        hex_byte
    }

    fn set_mss(&mut self, mss: u16) -> &mut Packet {
        self.synchronize_mss = mss;
        
        self
    }

    fn get_mutable(&mut self) -> &mut Packet {
        self
    }
}

fn split_packet_tcp(packet: Vec<u8>, config: Config) -> PacketAbstraction {
    // Find SNI by lookup of domain name via pattern scanning
    
    let mut split_packet: Vec<Packet> = vec![Packet::new(100, false, false), Packet::new(100, false, false)];
    
    const LEAST_DOMAIN_HALF: u8 = 3;
    const SNI_OFFSET: u8 = 43;
    const CERT_ENCRYPTION_OFFSET: u8 = SNI_OFFSET - 11;
    let fake_ttl: u8 = config.fake_default_ttl.clone();
    
    for iteration in 0..packet.len() {
        if iteration < (SNI_OFFSET + LEAST_DOMAIN_HALF + config.split_offset).into() && config.split_sni {
            split_packet[0].push(packet[iteration]);
        } else {
            // Split certificate if enabled
            
            if config.split_certificate && iteration < (CERT_ENCRYPTION_OFFSET + config.split_offset).into() {
                split_packet[1].push(packet[iteration]);
            } else {
                if split_packet.len() <= 2 {
                    split_packet.push(Packet::new(100, false, false));
                }
                
                split_packet[2].push(packet[iteration]);
            }
        }
    }
    
    let mut packet: PacketAbstraction = PacketAbstraction {
        split_parts: split_packet
            .into_iter()
            .filter(|vector| vector.raw_body.len() as u8 != 0)
            .map(|mut packet| packet.get_mutable().set_mss(config.raw_socket_mss).clone())
            .collect(),
        send_after_inbound: vec![]
    };
    
    if config.disorder_corrupt_ttl {
        packet.split_parts[0].time_to_live = 1;
    };
    
    if config.disorder_fake_packet {
        // Different scenarios exist, if we're splitting SNI - put fake part 
        // Of yandex.ru SNI. If we're splitting certificate,
        // Put fake one signed by Russian CA Authority, which is untrusted
        // By default in case on Russian DPIs, but tricks DPI into 
        // Decoding traffic completely wrong
        
        if config.split_sni {
            let fake_sni: Vec<u8> = config.fake_sni_clienthello.clone();
            
            let mut packet_fake_sni: Packet = Packet::new(fake_ttl, false, false);
            
            packet_fake_sni.raw_body = fake_sni;
            packet_fake_sni.synchronize_mss = config.fake_packet_mss;
            
            packet.send_after_inbound.push(packet_fake_sni);
        }
        
        if config.split_certificate {
            // Put random data, to trick DPI into selecting random
            // Cipher
            
            let mut packet_fake_cert: Packet = Packet::new(fake_ttl, false, false);
            
            packet_fake_cert.raw_body = config.fake_certificate_common.clone();
            packet_fake_cert.synchronize_mss = config.fake_packet_mss;

            packet.send_after_inbound.push(packet_fake_cert);
        }
    }
    
    if config.fake_generate_clienthello && packet.split_parts[0].raw_body[0] == 0x16 {
        let mut fake_packet_clienthello: Packet = Packet::new(fake_ttl, false, false);
        
        fake_packet_clienthello.raw_body = config.fake_packet_clienthello;
        fake_packet_clienthello.synchronize_mss = config.fake_packet_mss;

        packet.send_after_inbound.push(fake_packet_clienthello);
    }
    
    if config.fake_generate_serverhello && packet.split_parts[0].raw_body[0] == 0x01 {
        let mut fake_serverhello: Packet = Packet::new(fake_ttl, false, false);
        
        fake_serverhello.raw_body = config.fake_serverhello;
        fake_serverhello.synchronize_mss = config.fake_packet_mss;
        
        packet.send_after_inbound.push(fake_serverhello);
    }
    
    if config.out_of_band && packet.split_parts[0].raw_body[0] <= 0x16 {
        let mut oob_data: Packet = Packet::new(fake_ttl, false, true);
        
        oob_data.raw_body = vec![config.out_of_band_byte];
        oob_data.synchronize_mss = config.fake_packet_mss;
        
        packet.send_after_inbound.push(oob_data);
    }
    
    packet
}

fn process_server_message_tcp(packet: Vec<u8>, config: Config) -> PacketAbstraction {
    let fake_ttl: u8 = config.fake_default_ttl.clone();
    let mut server_packet: Packet = Packet::new(100, false, false);
    let mut send_after_inbound: Vec<Packet> = vec![Packet::new(fake_ttl, false, false)];
    
    server_packet.raw_body = packet.clone();
    
    // Add fake SACK if ServerHello received
    
    if packet[0] == 0x02 && config.fake_generate_sack {
        let mut fake_sack: Packet = Packet::new(1, false, false);
        
        fake_sack.raw_body = config.fake_sack;
        fake_sack.synchronize_mss = config.fake_packet_mss;
        
        send_after_inbound.push(fake_sack);
    }
    
    // Make fake handshake (default: fake cipher choise) if
    // Server encrypted extensions received
    
    if packet[0] == 0x03 && config.fake_generate_handshake {
        let mut fake_handshake: Packet = Packet::new(1, false, false);
        
        fake_handshake.raw_body = config.fake_packet_certificate;
        fake_handshake.synchronize_mss = config.fake_packet_mss;
        
        send_after_inbound.push(fake_handshake);
    }
    
    // Pattern scan packet for bytes of autocorrupt_url
    
    if config.server_drop_if_autocorrupt {
        let string_bytes: Vec<u8> = config.autocorrupt_url.into_bytes();
        
        let mut vec_iter = packet.iter();
        let mut bytes_iter = string_bytes.iter();
        
        if bytes_iter.all(|byte| vec_iter.any(|byte_n| byte == byte_n)) {
            println!("[!!] PANIC!! Dropping packet!");
            
            // Set server packet TTL to 0, to force it to be ignored
            
            server_packet.time_to_live = 0;
        }
    }
    
    let split_parts: Vec<Packet> = vec![server_packet];
    
    let packet: PacketAbstraction = PacketAbstraction {
        split_parts, 
        send_after_inbound: send_after_inbound
            .into_iter()
            .filter(|packet| packet.raw_body.len() != 0)
            .map(|mut packet| packet.get_mutable().set_mss(config.raw_socket_mss).clone())
            .collect()
    };
    
    packet
}

fn process_packet_udp(packet: &mut Packet) -> &mut Packet {
    packet
}

fn socks5_proxy(proxy_client: &mut TcpStream) {
    let client: TcpStream = proxy_client.try_clone().unwrap();

    println!("Connection complete: {:?}", client);
}

fn main() {
    let config: Config = Config {
        split_sni: true,
        split_certificate: true,
        split_offset: 1,
        raw_socket_mss: 900,
    
        disorder_corrupt_ttl: true,
        disorder_fake_packet: true,
        
        out_of_band_byte: 213,
        out_of_band: true,
    
        fake_default_ttl: 2,
        fake_bad_sequence_num: true, // TODO
        fake_bad_sequence_increment: -10000, // TODO
        fake_bad_md5_sign: true, // TODO
        fake_packet_mss: 666,
 
        fake_generate_clienthello: true,
        fake_generate_serverhello: true,
        fake_generate_sack: true,
        fake_generate_handshake: true,
        fake_generate_certificate: true,
           
        fake_packet_certificate: vec![0, 0],
        fake_packet_clienthello: vec![0, 0],
        fake_sni_clienthello: vec![0, 0],
        fake_certificate_common: vec![0, 0],
        fake_serverhello: vec![0, 0],
        fake_sack: vec![0, 0],
        fake_quic_initial: vec![0, 0], // TODO
        fake_udp_datagram: vec![0, 0], // TODO
    
        http_host_random_case: true, // TODO
        http_host_spelling: String::from("hOSt"), // TODO
        http_domain_random_case: true, // TODO

        autocorrupt_url: String::from("blacklist.planeta.tc"),
        
        server_drop_if_autocorrupt: true,
    };

    /**
    == EXAMPLE ==

    let packet: Vec<u8> = vec![
        0x16, 0x03, 0x03, 0x00, 0xC8, 0x01, 0x00, 0xB8,
        0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x06, 0x00, 0x35, 0x00, 0x3C, 0x00,
        0xBA, 0x01, 0x00, 0x00, 0x30, 0x00, 0x08, 0x08,
        0x06, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x2E, 0x63, 0x6F, 0x6D, 0x2B, 0x03, 0x03, 0x0A,
        0x0C, 0x00, 0x17, 0x00, 0x18,
    ];
    
    let packets_split: PacketAbstraction = split_packet_tcp(packet.clone(), config.clone());
    let packets_data: PacketAbstraction = process_server_message_tcp(packet.clone(), config.clone());
    **/

    println!("Waterfall config: {:#?}", config);
    
    /// println!("[LOGGER] Client data: {:#?}", packets_split);
    /// println!("[LOGGER] Server data: {:#?}", packets_data);

    let listener: TcpListener = TcpListener::bind("127.0.0.1:7878").unwrap();
    
    for stream in listener.incoming() {
        match stream {
            Ok(mut client) => socks5_proxy(&mut client),
            Err(error) => println!("Socks5 proxy encountered an error: {}", error)
        };
    }
}
