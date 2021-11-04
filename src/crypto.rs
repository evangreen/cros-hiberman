// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement image symmetric encryption functionality.

use std::io::{IoSlice, IoSliceMut, Read, Write};
use openssl::symm::{Cipher, Crypter, Mode};
use crate::hibermeta::{HIBERNATE_DATA_IV_SIZE, HIBERNATE_DATA_KEY_SIZE};
use crate::hiberutil::Result;
use crate::mmapbuf::MmapBuffer;

/// Define the size of a symmetric encryption block. If the encryption algorithm
/// is changed, be sure to keep this value in sync.
const CRYPTO_BLOCK_SIZE: usize = HIBERNATE_DATA_KEY_SIZE;

/// The CryptoWriter is an object that can be inserted in the image pipeline on
/// the "write" side (in other words, somewhere on the destination side of the
/// ImageMover). When written to, it will encrypt or decrypt contents and then
/// pass them on to its pre-arranged destination.
pub struct CryptoWriter<'a> {
    crypter: Crypter,
    dest_file: &'a mut dyn Write,
    buffer: MmapBuffer,
    buffer_size: usize,
}

impl<'a> CryptoWriter<'a> {
    /// Set up a new CryptoWriter with the given write destination, key, and
    /// mode (encrypt or decrypt). The buffer_size argument lets this structure
    /// know how big of an internal buffer to allocate, representing the maximum
    /// chunk size that will be passed to the final destination writes.
    pub fn new(
        dest_file: &'a mut dyn Write,
        key: [u8; HIBERNATE_DATA_KEY_SIZE],
        iv: [u8; HIBERNATE_DATA_IV_SIZE],
        encrypt: bool,
        buffer_size: usize,
    ) -> Result<Self> {
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
        let buffer = MmapBuffer::new(buffer_size + CRYPTO_BLOCK_SIZE)?;
        Ok(Self {
            crypter,
            dest_file,
            buffer,
            buffer_size,
        })
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
            let dst_end = size_this_round + CRYPTO_BLOCK_SIZE;
            let src_end = offset + size_this_round;
            let crypto_count = self
                .crypter
                .update(
                    &buf[offset..src_end],
                    &mut self.buffer.u8_slice_mut()[..dst_end],
                )
                .unwrap();

            assert!(
                crypto_count == size_this_round,
                "Expected {} crypt bytes, got {}",
                size_this_round,
                crypto_count
            );

            // Do the write.
            let slice = [IoSlice::new(&self.buffer.u8_slice()[..crypto_count])];
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

/// The CryptoReader object is nearly identical to the CryptoWriter struct,
/// except it supports being hooked up on the read side of the ImageMover.
/// Implementing the read side is significantly more annoying than implementing
/// the write side because of OpenSSL's requirement that the crypto output
/// buffer be at least one block larger than the input buffer. It would be
/// fairly simple to just decrypt to a separate buffer first, but that results
/// in an extra buffer copy, which we'd like to avoid for what's potentially a
/// multi-gigabyte operation. Instead, we decrypt as much as we can directly to
/// the destination buffer, minus one block. We then do that block into a
/// separate buffer, so that we minimize the extra copies.
pub struct CryptoReader<'a> {
    crypter: Crypter,
    source_file: &'a mut dyn Read,
    buffer: MmapBuffer,
    buffer_size: usize,
    extra: MmapBuffer,
    extra_offset: usize,
    extra_size: usize,
}

impl<'a> CryptoReader<'a> {
    /// Create a new CryptoReader with the given source file, encryption key,
    /// and mode (encrypt or decrypt). The buffer size indicates how big of an
    /// internal buffer to create, which also represents the maximum sized read
    /// that will ever be done from the source. Size this based on your expected
    /// average read size.
    pub fn new(
        source_file: &'a mut dyn Read,
        key: [u8; HIBERNATE_DATA_KEY_SIZE],
        iv: [u8; HIBERNATE_DATA_IV_SIZE],
        encrypt: bool,
        buffer_size: usize,
    ) -> Result<Self> {
        let cipher = Cipher::aes_128_cbc();
        let mode = match encrypt {
            true => Mode::Encrypt,
            false => Mode::Decrypt,
        };

        let mut crypter = Crypter::new(cipher, mode, &key, Some(&iv)).unwrap();
        crypter.pad(false);
        let buffer = MmapBuffer::new(buffer_size)?;
        let extra = MmapBuffer::new(buffer_size + CRYPTO_BLOCK_SIZE)?;
        Ok(Self {
            crypter,
            source_file,
            buffer,
            buffer_size,
            extra,
            extra_offset: 0,
            extra_size: 0,
        })
    }
}

impl Read for CryptoReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let extra = self.extra.u8_slice_mut();
        let mut offset = 0usize;
        let length = buf.len();
        let source_buf = self.buffer.u8_slice_mut();

        // There's currently no need for the complexity of partial blocks.
        assert!(
            (length % CRYPTO_BLOCK_SIZE) == 0,
            "Encryption requested I/O length {} not a multiple of {}",
            length,
            CRYPTO_BLOCK_SIZE
        );

        // Loop converting internal buffer sized chunks.
        while offset < length {
            // If there's extra data from before, grab that.
            if self.extra_offset < self.extra_size {
                let mut extra_size = self.extra_size - self.extra_offset;
                if extra_size > length - offset {
                    extra_size = length - offset;
                }

                let dst_end = offset + extra_size;
                let src_end = self.extra_offset + extra_size;
                buf[offset..dst_end].copy_from_slice(&extra[self.extra_offset..src_end]);
                offset += extra_size;
                self.extra_offset += extra_size;
                continue;
            }

            // Fill the source buffer, but not more than the caller wants, since
            // we're trying to minimize copies into the extra buffer.
            let mut size_this_round = self.buffer_size;
            if size_this_round > (length - offset) {
                size_this_round = length - offset;
            }

            assert!((size_this_round % CRYPTO_BLOCK_SIZE) == 0);

            let mut slice = [IoSliceMut::new(&mut source_buf[..size_this_round])];
            let source_bytes = self.source_file.read_vectored(&mut slice)?;
            if source_bytes == 0 {
                break;
            }

            assert!((source_bytes % CRYPTO_BLOCK_SIZE) == 0);

            // Process as much as possible directly into the caller's buffer.
            // Unfortunately the destination has to be oversized by one block,
            // so the last block has to bounce though another buffer.
            let direct_count = source_bytes - CRYPTO_BLOCK_SIZE;
            let dst_end = offset + source_bytes;
            offset += self
                .crypter
                .update(&source_buf[..direct_count], &mut buf[offset..dst_end])
                .unwrap();

            // Decrypt the last block into the extra buffer.
            self.extra_offset = 0;
            self.extra_size = self
                .crypter
                .update(&source_buf[direct_count..source_bytes], extra)
                .unwrap();
        }

        Ok(offset)
    }
}
