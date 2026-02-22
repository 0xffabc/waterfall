pub struct Random {
    last_num: u32,

    magic_mul: u32,
    magic_add: u32,
}

impl Random {
    pub fn new(initial: u32) -> Self {
        Self {
            last_num: initial,
            magic_mul: 1664525,
            magic_add: 1013904223,
        }
    }

    fn clamp_low_bits(&self, num: &u32) -> u32 {
        num >> 16
    }

    pub fn next_rand(&mut self) -> u8 {
        self.last_num = self
            .last_num
            .wrapping_mul(self.magic_mul)
            .wrapping_add(self.magic_add);

        self.clamp_low_bits(&self.last_num) as u8
    }
}

pub fn make_random_vec(len: usize, seed: u32) -> Vec<u8> {
    let mut rand: Random = Random::new(seed);

    (0..len).map(|_| rand.next_rand()).collect()
}
