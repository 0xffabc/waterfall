pub struct Sni();

impl Sni {
    pub fn parse_sni_index(source: Vec<u8>) -> (u32, u32) {
        if source.is_empty() || source[0] != 0x16 {
            return (0, 0);
        };

        if source.len() < 48 {
            return (0, 0);
        };

        if source.len() <= 5 || source[5] != 0x01 {
            return (0, 0);
        };

        (0..source.len().saturating_sub(8))
            .find_map(|i| {
                if source[i] == 0x00
                    && source[i + 1] == 0x00
                    && source[i + 7] == 0x00
                    && (source[i + 3] as isize - source[i + 5] as isize) == 2
                {
                    let len = source[i + 8] as usize;

                    let start = i + 9;
                    let end = start + len as usize;

                    if end <= source.len() && len > 0 && len < 256 {
                        return Some((start as u32, end as u32));
                    }
                }

                None
            })
            .unwrap_or((0, 0))
    }
}
