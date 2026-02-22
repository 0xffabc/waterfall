pub struct Flag {
    pub inner: u8,
}

impl Flag {
    fn set_field_to(&mut self, fnum: u8, val: bool) {
        if val {
            self.inner |= 1 << fnum;
        } else {
            self.inner &= !(1 << fnum);
        }
    }

    pub fn set_cwr(&mut self, val: bool) {
        self.set_field_to(7, val);
    }

    pub fn set_ece(&mut self, val: bool) {
        self.set_field_to(6, val);
    }

    pub fn set_urg(&mut self, val: bool) {
        self.set_field_to(5, val);
    }

    pub fn set_ack(&mut self, val: bool) {
        self.set_field_to(4, val);
    }

    pub fn set_psh(&mut self, val: bool) {
        self.set_field_to(3, val);
    }

    pub fn set_rst(&mut self, val: bool) {
        self.set_field_to(2, val);
    }

    pub fn set_syn(&mut self, val: bool) {
        self.set_field_to(1, val);
    }

    pub fn set_fin(&mut self, val: bool) {
        self.set_field_to(0, val);
    }
}

pub struct TCPHeader {
    pub src: u16,
    pub dst: u16,
    pub seqnum: u32,
    pub acknum: u32,
    pub data_offset: u32,
    pub reserved: u8,
    pub flags: Flag,
    pub window: u16,
    pub urg_pointer: u16,
    pub checksum: u16,
}

impl Into<Vec<u8>> for TCPHeader {
    fn into(self) -> Vec<u8> {
        let mut header = vec![];

        if self.data_offset > 32 * (16 - 5) {
            panic!("Cannot fit data_offset/8 into a u4");
        }

        header.extend_from_slice(&self.src.to_be_bytes());
        header.extend_from_slice(&self.dst.to_be_bytes());
        header.extend_from_slice(&self.seqnum.to_be_bytes());
        header.extend_from_slice(&self.acknum.to_be_bytes());

        header.push(((self.data_offset & 0x0F) as u8) << 4 | (self.reserved & 0x0F));
        header.push(self.flags.inner);

        header.extend_from_slice(&self.window.to_be_bytes());
        header.extend_from_slice(&self.checksum.to_be_bytes());
        header.extend_from_slice(&self.urg_pointer.to_be_bytes());
        header.extend_from_slice(&self.data_offset.to_be_bytes());

        header
    }
}
