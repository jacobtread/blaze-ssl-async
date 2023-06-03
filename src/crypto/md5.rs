//! This is a modified slimmed down implementation of the RustCrypto md5 + sha1 code
//! see <https://github.com/DaGenix/rust-crypto>

use super::buffer::Buffer;
use std::ptr;

const DEFAULT_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

// Round 1 constants
static C1: [u32; 16] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
];

// Round 2 constants
static C2: [u32; 16] = [
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
];

// Round 3 constants
static C3: [u32; 16] = [
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
];

// Round 4 constants
static C4: [u32; 16] = [
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

pub struct Md5 {
    length_bytes: u64,
    buffer: Buffer,
    state: [u32; 4],
}

impl Md5 {
    pub fn new() -> Md5 {
        Md5 {
            length_bytes: 0,
            buffer: Buffer::new(),
            state: DEFAULT_STATE,
        }
    }

    pub fn input(&mut self, input: &[u8]) {
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| {
            Self::process_block(self_state, d);
        });
    }

    pub fn reset(&mut self) {
        self.length_bytes = 0;
        self.buffer.reset();
        self.state = DEFAULT_STATE;
    }

    pub fn result(&mut self, out: &mut [u8]) {
        // Finish
        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |d: &[u8]| {
            Self::process_block(self_state, d);
        });
        write_u32_le(self.buffer.next(4), (self.length_bytes << 3) as u32);
        write_u32_le(self.buffer.next(4), (self.length_bytes >> 29) as u32);
        Self::process_block(self_state, self.buffer.full_buffer());

        // Write output
        write_u32_le(&mut out[0..4], self.state[0]);
        write_u32_le(&mut out[4..8], self.state[1]);
        write_u32_le(&mut out[8..12], self.state[2]);
        write_u32_le(&mut out[12..16], self.state[3]);
    }

    fn process_block(state: &mut [u32; 4], input: &[u8]) {
        fn op_f(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add((x & y) | (!x & z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_g(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add((x & z) | (y & !z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_h(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(x ^ y ^ z)
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_i(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(y ^ (x | !z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        let [mut a, mut b, mut c, mut d] = state;

        let mut data = [0u32; 16];

        read_u32v_le(&mut data, input);

        // round 1
        let mut i = 0;
        while i < 16 {
            a = op_f(a, b, c, d, data[i].wrapping_add(C1[i]), 7);
            d = op_f(d, a, b, c, data[i + 1].wrapping_add(C1[i + 1]), 12);
            c = op_f(c, d, a, b, data[i + 2].wrapping_add(C1[i + 2]), 17);
            b = op_f(b, c, d, a, data[i + 3].wrapping_add(C1[i + 3]), 22);

            i += 4;
        }

        // round 2
        let mut t = 1;

        i = 0;
        while i < 16 {
            a = op_g(a, b, c, d, data[t & 0x0f].wrapping_add(C2[i]), 5);
            d = op_g(d, a, b, c, data[(t + 5) & 0x0f].wrapping_add(C2[i + 1]), 9);
            c = op_g(
                c,
                d,
                a,
                b,
                data[(t + 10) & 0x0f].wrapping_add(C2[i + 2]),
                14,
            );
            b = op_g(
                b,
                c,
                d,
                a,
                data[(t + 15) & 0x0f].wrapping_add(C2[i + 3]),
                20,
            );
            t += 20;
            i += 4;
        }

        // round 3
        t = 5;
        i = 0;
        while i < 16 {
            a = op_h(a, b, c, d, data[t & 0x0f].wrapping_add(C3[i]), 4);
            d = op_h(d, a, b, c, data[(t + 3) & 0x0f].wrapping_add(C3[i + 1]), 11);
            c = op_h(c, d, a, b, data[(t + 6) & 0x0f].wrapping_add(C3[i + 2]), 16);
            b = op_h(b, c, d, a, data[(t + 9) & 0x0f].wrapping_add(C3[i + 3]), 23);
            t += 12;
            i += 4;
        }

        // round 4
        t = 0;
        i = 0;
        while i < 16 {
            a = op_i(a, b, c, d, data[t & 0x0f].wrapping_add(C4[i]), 6);
            d = op_i(d, a, b, c, data[(t + 7) & 0x0f].wrapping_add(C4[i + 1]), 10);
            c = op_i(
                c,
                d,
                a,
                b,
                data[(t + 14) & 0x0f].wrapping_add(C4[i + 2]),
                15,
            );
            b = op_i(
                b,
                c,
                d,
                a,
                data[(t + 21) & 0x0f].wrapping_add(C4[i + 3]),
                21,
            );
            t += 28;
            i += 4;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in little-endian
/// format.
pub fn write_u32_le(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_le();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

/// Read a vector of bytes into a vector of u32s. The values are read in little-endian format.
pub fn read_u32v_le(dst: &mut [u32], input: &[u8]) {
    assert!(dst.len() * 4 == input.len());
    unsafe {
        let mut x: *mut u32 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u32 = 0;
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 4);
            *x = u32::from_le(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}
