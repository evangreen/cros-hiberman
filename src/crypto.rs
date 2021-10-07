// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement image encryption/decryption functionality.

use crate::hibermeta::{HIBERNATE_DATA_IV_SIZE, HIBERNATE_DATA_KEY_SIZE};
use crate::hiberutil::{buffer_alignment_offset, DIRECT_IO_ALIGNMENT};
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{IoSlice, Write};

const CRYPTO_BLOCK_SIZE: usize = HIBERNATE_DATA_KEY_SIZE;
const CRYPTO_BUFFER_ALIGNMENT: usize = DIRECT_IO_ALIGNMENT;

pub struct CryptoWriter<'a> {
    crypter: Crypter,
    dest_file: &'a mut dyn Write,
    buffer_size: usize,
    buffer: Vec<u8>,
    offset: usize,
}

impl<'a> CryptoWriter<'a> {
    pub fn new(
        dest_file: &'a mut dyn Write,
        key: [u8; HIBERNATE_DATA_KEY_SIZE],
        iv: [u8; HIBERNATE_DATA_IV_SIZE],
        encrypt: bool,
        buffer_size: usize,
    ) -> Self {
        let cipher = Cipher::aes_128_cbc();
        let mode = match encrypt {
            true => Mode::Encrypt,
            false => Mode::Decrypt,
        };

        let mut crypter = Crypter::new(cipher, mode, &key, Some(&iv)).unwrap();
        crypter.pad(false);
        // Pad the buffer not only for alignment, but because Crypter::Update()
        // wants an extra block in the output buffer in case there were
        // leftovers from last time.
        let buffer = vec![0u8; buffer_size + CRYPTO_BLOCK_SIZE + CRYPTO_BUFFER_ALIGNMENT];
        let offset = buffer_alignment_offset(&buffer, CRYPTO_BUFFER_ALIGNMENT);
        Self {
            crypter,
            dest_file,
            buffer_size,
            buffer,
            offset,
        }
    }
}

impl Write for CryptoWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0usize;
        let length = buf.len();

        // There's currently no need for the complexity of partial blocks.
        assert!(
            (length % CRYPTO_BLOCK_SIZE) == 0,
            "Encryption requested I/O length {} not a multiple of {}",
            length,
            CRYPTO_BLOCK_SIZE
        );

        // Loop converting internal buffer sized chunks.
        while offset < length {
            let mut size_this_round = self.buffer_size;
            if size_this_round > (length - offset) {
                size_this_round = length - offset;
            }

            // Decrypt or encrypt into the aligned buffer. It's overallocated
            // by a block because the Crypter panics if the output isn't
            // overallocated by a block to accommodate a possible extra block
            // from leftovers. We always call with lengths that are multiples
            // of the block size.
            let dst_start = self.offset;
            let dst_end = dst_start + size_this_round + CRYPTO_BLOCK_SIZE;
            let src_end = offset + size_this_round;
            let crypto_count = self
                .crypter
                .update(&buf[offset..src_end], &mut self.buffer[dst_start..dst_end])
                .unwrap();

            assert!(
                crypto_count == size_this_round,
                "Expected {} crypt bytes, got {}",
                size_this_round,
                crypto_count
            );

            // Do the write.
            let dst_end = dst_start + crypto_count;
            let slice = [IoSlice::new(&self.buffer[dst_start..dst_end])];
            let bytes_done = self.dest_file.write_vectored(&slice)?;
            if bytes_done == 0 {
                break;
            }

            offset += bytes_done;
        }

        Ok(offset)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.dest_file.flush()
    }
}