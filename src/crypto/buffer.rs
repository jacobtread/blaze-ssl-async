//! This is a modified slimmed down implementation of the RustCrypto md5 + sha1 code
//! see <https://github.com/DaGenix/rust-crypto>

use std::ptr;

pub struct Buffer {
    buffer: [u8; 64],
    cursor: usize,
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer {
            buffer: [0u8; 64],
            cursor: 0,
        }
    }
}

impl Buffer {
    #[inline]
    pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
        assert!(dst.len() >= src.len());
        unsafe {
            let srcp = src.as_ptr();
            let dstp = dst.as_mut_ptr();
            ptr::copy_nonoverlapping(srcp, dstp, src.len());
        }
    }

    pub fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
        let mut i = 0;

        if self.cursor != 0 {
            let buffer_remaining = 64 - self.cursor;
            if input.len() >= buffer_remaining {
                Self::copy_memory(
                    &input[..buffer_remaining],
                    &mut self.buffer[self.cursor..64],
                );
                self.cursor = 0;
                func(&self.buffer);
                i += buffer_remaining;
            } else {
                Self::copy_memory(
                    input,
                    &mut self.buffer[self.cursor..self.cursor + input.len()],
                );
                self.cursor += input.len();
                return;
            }
        }

        while input.len() - i >= 64 {
            func(&input[i..i + 64]);
            i += 64;
        }

        let input_remaining = input.len() - i;
        Self::copy_memory(&input[i..], &mut self.buffer[0..input_remaining]);
        self.cursor += input_remaining;
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    pub fn zero_until(&mut self, idx: usize) {
        assert!(idx >= self.cursor);
        let dst = &mut self.buffer[self.cursor..idx];
        // Zero all bytes in dst
        unsafe {
            ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
        }
        self.cursor = idx;
    }

    pub fn next(&mut self, len: usize) -> &mut [u8] {
        self.cursor += len;
        &mut self.buffer[self.cursor - len..self.cursor]
    }

    pub fn full_buffer(&mut self) -> &[u8] {
        assert!(self.cursor == 64);
        self.cursor = 0;
        &self.buffer[..64]
    }

    pub fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, mut func: F) {
        self.next(1)[0] = 128;

        if (64 - self.cursor) < rem {
            self.zero_until(64);
            func(self.full_buffer());
        }

        self.zero_until(64 - rem);
    }
}
