#[repr(u8)]
#[derive(Clone)]
pub enum AFBGroup {
    LowClass1 = 0x0A,
    MediumClass1 = 0x0C,
    HighClass1 = 0x0E,
    LowClass2 = 0x12,
    MediumClass2 = 0x14,
    HighClass2 = 0x16,
    LowClass3 = 0x1A,
    MediumClass3 = 0x1C,
    HighClass3 = 0x1E,
    LowClass4 = 0x22,
    MediumClass4 = 0x24,
    HighClass4 = 0x26,
}

#[repr(u8)]
#[derive(Clone)]
pub enum ClassSelectorMapping {
    Standard = 0,
    LowPriority = 8,
    OAM = 16,
    Broadcast = 24,
    RealTime = 32,
    Signaling = 40,
    Routing = 48,
    Reserved = 56,
}

pub enum DSCPValue {
    AFB(AFBGroup),
    CSM(ClassSelectorMapping),
}

impl DSCPValue {
    pub fn as_u8(&self) -> u8 {
        match self {
            DSCPValue::AFB(int) => int.clone() as u8,
            DSCPValue::CSM(int) => int.clone() as u8,
        }
    }
}

#[repr(u8)]
pub enum ECNValue {
    NonECT = 0b00000000,
    ECT1 = 0b00000001,
    ECT = 0b00000010,
    CE = 0b00000011,
}

#[repr(u64)]
pub enum FragmentationFlags {
    Df = 0b01000000,
    Mf = 0b00100000,
    DfMf = 0b01100000,

    /*
     * The following group is useful for building
     * IPv4 packets that would be discarded by the DPI
     * if your router ignores the reserved field (somehow)
     */
    RDf = 0b11000000,
    RMf = 0b10100000,
    RDfMf = 0b11100000,
}

#[repr(u8)]
pub enum Protocol {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    IPv6Encapsulation = 41,
    OSPF = 89,
    SCTP = 132,
}

pub struct IPv4Header {
    pub ihl: u8,
    pub dscp: DSCPValue,
    pub ecn: ECNValue,
    pub length: u16,
    pub identification: u16,
    pub fragmentation_flags: FragmentationFlags,
    /* Panics if more than 2**13 - 1 */
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub checksum: u16,
    pub src: u32,
    pub dst: u32,
}

const IP_VERSION: u8 = 4;

fn crc16(bytes: &[u8]) -> u16 {
    let mut sum = 0;

    for u in bytes.chunks(2) {
        sum += u16::from_be_bytes([u[0], u[1]]) as u32;

        while sum > 0b1111111111111111 {
            sum = (sum & 0b1111111111111111) | (sum >> 16);
        }
    }

    !(sum as u16)
}

impl Into<Vec<u8>> for IPv4Header {
    fn into(self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.push(IP_VERSION << 4 | self.ihl);
        bytes.push(self.dscp.as_u8() << 2 | (self.ecn as u8));
        bytes.extend_from_slice(&self.identification.to_be_bytes());

        let fragment_data = (self.fragmentation_flags as u16) << 13 | self.fragment_offset;

        bytes.extend_from_slice(&fragment_data.to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(self.protocol as u8);

        bytes.extend_from_slice(&[0, 0]);

        bytes.extend_from_slice(&self.src.to_be_bytes());
        bytes.extend_from_slice(&self.dst.to_be_bytes());

        let crc: [u8; 2] = crc16(&bytes).to_be_bytes();

        bytes[11] = crc[0];
        bytes[12] = crc[1];

        bytes
    }
}
