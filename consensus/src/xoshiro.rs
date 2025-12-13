// Xoshiro256++ Implementation
pub struct Xoshiro256PlusPlus {
    s: [u64; 4],
}

impl Xoshiro256PlusPlus {
    pub fn new(seed: u64) -> Self {
        let mut s = [0u64; 4];
        s[0] = Self::splitmix64(seed);
        s[1] = Self::splitmix64(seed);
        s[2] = Self::splitmix64(seed);
        s[3] = Self::splitmix64(seed);
        Self { s }
    }

    fn rotl(x: u64, k: i32) -> u64 {
        (x << k) | (x >> (64 - k))
    }

    fn splitmix64(x: u64) -> u64 {
        let mut z = x.wrapping_add(0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    pub fn next(&mut self) -> u64 {
        let result = Self::rotl(self.s[0].wrapping_add(self.s[3]), 23).wrapping_add(self.s[0]);

        let t = self.s[1] << 17;

        self.s[2] ^= self.s[0];
        self.s[1] ^= self.s[1];
        self.s[0] ^= self.s[2];
        self.s[3] ^= self.s[1];

        self.s[1] ^= t;
        self.s[3] = Self::rotl(self.s[3], 45);

        result
    }

    pub fn next_float(&mut self) -> f32 {
        let r = (self.next() >> 40) as u32;
        let f = (r as f32) / ((1 << 24) as f32);
        f * 2.0 - 1.0
    }
}








