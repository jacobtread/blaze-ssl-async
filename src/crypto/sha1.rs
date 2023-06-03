//! This is a modified slimmed down implementation of the RustCrypto md5 + sha1 code
//! see <https://github.com/DaGenix/rust-crypto>

use super::buffer::Buffer;
use std::{
    ops::{Add, BitXor, Sub},
    ptr,
};

const BLOCK_LEN: usize = 16;
const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;
const DEFAULT_STATE: [u32; 5] = [
    0x67452301u32,
    0xEFCDAB89u32,
    0x98BADCFEu32,
    0x10325476u32,
    0xC3D2E1F0u32,
];

pub struct Sha1 {
    h: [u32; 5],
    length_bits: u64,
    buffer: Buffer,
}

impl Sha1 {
    pub fn new() -> Sha1 {
        Sha1 {
            h: DEFAULT_STATE,
            length_bits: 0,
            buffer: Buffer::new(),
        }
    }

    pub fn reset(&mut self) {
        self.length_bits = 0;
        self.h = DEFAULT_STATE;
        self.buffer.reset();
    }

    pub fn input(&mut self, msg: &[u8]) {
        let bytes = msg.len() as u64;
        let new_high_bits = bytes >> 61;
        let new_low_bits = bytes << 3;

        if new_high_bits > 0 {
            panic!("Numeric overflow occured.")
        }

        self.length_bits = self
            .length_bits
            .checked_add(new_low_bits)
            .expect("Numeric overflow occured.");

        let st_h = &mut self.h;
        self.buffer.input(msg, |d: &[u8]| {
            Self::digest_block(st_h, d);
        });
    }

    pub fn digest_block(state: &mut [u32; 5], block: &[u8]) {
        assert_eq!(block.len(), BLOCK_LEN * 4);
        let mut block2 = [0u32; BLOCK_LEN];
        read_u32v_be(&mut block2[..], block);
        Self::digest_block_u32(state, &block2);
    }

    pub fn digest_block_u32(state: &mut [u32; 5], block: &[u32; 16]) {
        macro_rules! schedule {
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
                sha1msg2(sha1msg1($v0, $v1) ^ $v2, $v3)
            };
        }

        macro_rules! rounds4 {
            ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
                sha1_digest_round_x4($h0, sha1_first_half($h1, $wk), $i)
            };
        }

        // Rounds 0..20
        let mut h0 = u32x4(state[0], state[1], state[2], state[3]);
        let mut w0 = u32x4(block[0], block[1], block[2], block[3]);
        let mut h1 = sha1_digest_round_x4(h0, sha1_first_add(state[4], w0), 0);
        let mut w1 = u32x4(block[4], block[5], block[6], block[7]);
        h0 = rounds4!(h1, h0, w1, 0);
        let mut w2 = u32x4(block[8], block[9], block[10], block[11]);
        h1 = rounds4!(h0, h1, w2, 0);
        let mut w3 = u32x4(block[12], block[13], block[14], block[15]);
        h0 = rounds4!(h1, h0, w3, 0);
        let mut w4 = schedule!(w0, w1, w2, w3);
        h1 = rounds4!(h0, h1, w4, 0);

        // Rounds 20..40
        w0 = schedule!(w1, w2, w3, w4);
        h0 = rounds4!(h1, h0, w0, 1);
        w1 = schedule!(w2, w3, w4, w0);
        h1 = rounds4!(h0, h1, w1, 1);
        w2 = schedule!(w3, w4, w0, w1);
        h0 = rounds4!(h1, h0, w2, 1);
        w3 = schedule!(w4, w0, w1, w2);
        h1 = rounds4!(h0, h1, w3, 1);
        w4 = schedule!(w0, w1, w2, w3);
        h0 = rounds4!(h1, h0, w4, 1);

        // Rounds 40..60
        w0 = schedule!(w1, w2, w3, w4);
        h1 = rounds4!(h0, h1, w0, 2);
        w1 = schedule!(w2, w3, w4, w0);
        h0 = rounds4!(h1, h0, w1, 2);
        w2 = schedule!(w3, w4, w0, w1);
        h1 = rounds4!(h0, h1, w2, 2);
        w3 = schedule!(w4, w0, w1, w2);
        h0 = rounds4!(h1, h0, w3, 2);
        w4 = schedule!(w0, w1, w2, w3);
        h1 = rounds4!(h0, h1, w4, 2);

        // Rounds 60..80
        w0 = schedule!(w1, w2, w3, w4);
        h0 = rounds4!(h1, h0, w0, 3);
        w1 = schedule!(w2, w3, w4, w0);
        h1 = rounds4!(h0, h1, w1, 3);
        w2 = schedule!(w3, w4, w0, w1);
        h0 = rounds4!(h1, h0, w2, 3);
        w3 = schedule!(w4, w0, w1, w2);
        h1 = rounds4!(h0, h1, w3, 3);
        w4 = schedule!(w0, w1, w2, w3);
        h0 = rounds4!(h1, h0, w4, 3);

        let e = h1.0.rotate_left(30);
        let u32x4(a, b, c, d) = h0;

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    pub fn result(&mut self, out: &mut [u8]) {
        let st_h = &mut self.h;
        self.buffer
            .standard_padding(8, |d: &[u8]| Self::digest_block(&mut *st_h, d));
        write_u32_be(self.buffer.next(4), (self.length_bits >> 32) as u32);
        write_u32_be(self.buffer.next(4), self.length_bits as u32);
        Self::digest_block(st_h, self.buffer.full_buffer());

        write_u32_be(&mut out[0..4], self.h[0]);
        write_u32_be(&mut out[4..8], self.h[1]);
        write_u32_be(&mut out[8..12], self.h[2]);
        write_u32_be(&mut out[12..16], self.h[3]);
        write_u32_be(&mut out[16..20], self.h[4]);
    }
}

pub fn write_u32_be(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct u32x4(pub u32, pub u32, pub u32, pub u32);

impl Add for u32x4 {
    type Output = u32x4;

    fn add(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0.wrapping_add(rhs.0),
            self.1.wrapping_add(rhs.1),
            self.2.wrapping_add(rhs.2),
            self.3.wrapping_add(rhs.3),
        )
    }
}

impl Sub for u32x4 {
    type Output = u32x4;

    fn sub(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0.wrapping_sub(rhs.0),
            self.1.wrapping_sub(rhs.1),
            self.2.wrapping_sub(rhs.2),
            self.3.wrapping_sub(rhs.3),
        )
    }
}

impl BitXor for u32x4 {
    type Output = u32x4;

    fn bitxor(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}

#[inline]
pub fn sha1_first_add(e: u32, w0: u32x4) -> u32x4 {
    let u32x4(a, b, c, d) = w0;
    u32x4(e.wrapping_add(a), b, c, d)
}

fn sha1msg1(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(_, _, w2, w3) = a;
    let u32x4(w4, w5, _, _) = b;
    a ^ u32x4(w2, w3, w4, w5)
}

fn sha1msg2(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(x0, x1, x2, x3) = a;
    let u32x4(_, w13, w14, w15) = b;

    let w16 = (x0 ^ w13).rotate_left(1);
    let w17 = (x1 ^ w14).rotate_left(1);
    let w18 = (x2 ^ w15).rotate_left(1);
    let w19 = (x3 ^ w16).rotate_left(1);

    u32x4(w16, w17, w18, w19)
}

#[inline]
pub fn sha1_first_half(abcd: u32x4, msg: u32x4) -> u32x4 {
    sha1_first_add(abcd.0.rotate_left(30), msg)
}

pub fn sha1_digest_round_x4(abcd: u32x4, work: u32x4, i: i8) -> u32x4 {
    const K0V: u32x4 = u32x4(K0, K0, K0, K0);
    const K1V: u32x4 = u32x4(K1, K1, K1, K1);
    const K2V: u32x4 = u32x4(K2, K2, K2, K2);
    const K3V: u32x4 = u32x4(K3, K3, K3, K3);

    match i {
        0 => sha1rnds4c(abcd, work + K0V),
        1 => sha1rnds4p(abcd, work + K1V),
        2 => sha1rnds4m(abcd, work + K2V),
        3 => sha1rnds4p(abcd, work + K3V),
        _ => panic!("unknown icosaround index"),
    }
}

fn sha1rnds4c(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            $c ^ ($a & ($b ^ $c))
        };
    }

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_202!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_202!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_202!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_202!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

fn sha1rnds4p(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_150 {
        ($a:expr, $b:expr, $c:expr) => {
            $a ^ $b ^ $c
        };
    }

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_150!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_150!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_150!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_150!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

fn sha1rnds4m(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    }

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_232!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_232!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_232!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_232!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

pub fn read_u32v_be(dst: &mut [u32], input: &[u8]) {
    assert!(dst.len() * 4 == input.len());
    unsafe {
        let mut x: *mut u32 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u32 = 0;
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 4);
            *x = u32::from_be(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}
