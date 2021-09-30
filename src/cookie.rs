// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages the "valid resume image" cookie.

use crate::hiberutil::{
    buffer_alignment_offset, path_to_stateful_block, HibernateError, Result, DIRECT_IO_ALIGNMENT,
};
use std::fs::{File, OpenOptions};
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

struct HibernateCookie {
    blockdev: File,
    buf: Vec<u8>,
    offset: usize,
}

static HIBERNATE_COOKIE_READ_SIZE: usize = 0x400;
static HIBERNATE_COOKIE_WRITE_SIZE: usize = 0x400;
// Define the magic value the GPT stamps down, which we will use to
// verify we're writing to an area that is clear for us.
static GPT_MAGIC_OFFSET: usize = 0x200;
static GPT_MAGIC: u64 = 0x5452415020494645; // 'EFI PART'

// Define the alignment needed on hibernate cookie I/O.
static HIBERNATE_COOKIE_ALIGNMENT: usize = DIRECT_IO_ALIGNMENT;
// The beginning of the disk starts with a protective MBR, followed by
// a sector just for the GPT header. The GPT header is quite small and doesn't
// use its whole sector. Use the end of the sector to store the hibernate
// token.
static HIBERNATE_MAGIC_OFFSET: usize = 0x3E0;
// Define the magic token we write to indicate a valid hibernate partition.
static HIBERNATE_MAGIC: &str = "HibernateCookie!";
static HIBERNATE_MAGIC_POISON: &str = "HibernateInvalid";
static HIBERNATE_MAGIC_SIZE: usize = 16;

impl HibernateCookie {
    pub fn new(path: &Path) -> Result<HibernateCookie> {
        let blockdev = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT | libc::O_SYNC)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => return Err(HibernateError::OpenFileError(path.display().to_string(), e)),
        };

        let buf = vec![0u8; HIBERNATE_COOKIE_READ_SIZE + HIBERNATE_COOKIE_ALIGNMENT];
        let offset = buffer_alignment_offset(&buf, HIBERNATE_COOKIE_ALIGNMENT);
        Ok(HibernateCookie {
            blockdev,
            buf,
            offset,
        })
    }

    pub fn read(&mut self) -> Result<bool> {
        if let Err(e) = self.blockdev.seek(SeekFrom::Start(0)) {
            return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
        }

        let start = self.offset;
        let end = start + HIBERNATE_COOKIE_READ_SIZE;
        let mut slice_mut = [IoSliceMut::new(&mut self.buf[start..end])];
        let bytes_read = match self.blockdev.read_vectored(&mut slice_mut) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read < HIBERNATE_COOKIE_READ_SIZE {
            return Err(HibernateError::CookieError(format!(
                "Only read {:x?} bytes",
                bytes_read
            )));
        }

        // Verify there's a GPT header magic where there should be one.
        // This would catch cases like writing to the wrong place or the
        // GPT layout/location changing. This might need enlightenment for a
        // disk with 4kb blocks, this check will let us know that too.
        let gpt_sig_offset = self.offset + GPT_MAGIC_OFFSET;
        let gpt_sig_offset_end = gpt_sig_offset + 8;
        let mut gpt_sig = [0u8; 8];
        gpt_sig.copy_from_slice(&self.buf[gpt_sig_offset..gpt_sig_offset_end]);
        let gpt_sig = u64::from_le_bytes(gpt_sig);
        if gpt_sig != GPT_MAGIC {
            return Err(HibernateError::CookieError(format!(
                "GPT magic not found: {:x?}",
                gpt_sig
            )));
        }

        let magic_start = self.offset + HIBERNATE_MAGIC_OFFSET;
        let magic_end = magic_start + HIBERNATE_MAGIC_SIZE;
        let equal = self.buf[magic_start..magic_end] == *HIBERNATE_MAGIC.as_bytes();
        Ok(equal)
    }

    pub fn write(&mut self, valid: bool) -> Result<()> {
        let existing = self.read()?;
        if let Err(e) = self.blockdev.seek(SeekFrom::Start(0)) {
            return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
        }

        if valid == existing {
            return Ok(());
        }

        let magic_start = self.offset + HIBERNATE_MAGIC_OFFSET;
        let magic_end = magic_start + HIBERNATE_MAGIC_SIZE;
        let cookie = match valid {
            true => HIBERNATE_MAGIC,
            false => HIBERNATE_MAGIC_POISON,
        };

        self.buf[magic_start..magic_end].copy_from_slice(cookie.as_bytes());
        let start = self.offset;
        let end = start + HIBERNATE_COOKIE_WRITE_SIZE;
        let slice = [IoSlice::new(&self.buf[start..end])];
        let bytes_written = match self.blockdev.write_vectored(&slice) {
            Ok(s) => s,
            Err(e) => {
                return Err(HibernateError::FileIoError(
                    "Failed to write".to_string(),
                    e,
                ))
            }
        };

        if bytes_written < HIBERNATE_COOKIE_WRITE_SIZE {
            return Err(HibernateError::CookieError(format!(
                "Only wrote {:x?} bytes",
                bytes_written
            )));
        }

        if let Err(e) = self.blockdev.flush() {
            return Err(HibernateError::FileIoError(
                "Failed to flush".to_string(),
                e,
            ));
        }

        if let Err(e) = self.blockdev.sync_all() {
            return Err(HibernateError::FileIoError("Failed to sync".to_string(), e));
        }

        Ok(())
    }
}

pub fn get_hibernate_cookie(path_str: Option<&String>) -> Result<bool> {
    let stateful_block;
    let path = match path_str {
        None => {
            stateful_block = path_to_stateful_block()?;
            Path::new(&stateful_block)
        }
        Some(p) => Path::new(p),
    };

    let mut cookie = HibernateCookie::new(&path)?;
    cookie.read()
}

pub fn set_hibernate_cookie(path_str: Option<&String>, valid: bool) -> Result<()> {
    let stateful_block;
    let path = match path_str {
        None => {
            stateful_block = path_to_stateful_block()?;
            Path::new(&stateful_block)
        }
        Some(p) => Path::new(p),
    };

    let mut cookie = HibernateCookie::new(&path)?;
    cookie.write(valid)
}
