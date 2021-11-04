// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages the "valid resume image" cookie.

use std::fs::{File, OpenOptions};
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use crate::hiberutil::{path_to_stateful_block, HibernateError, Result};
use crate::mmapbuf::MmapBuffer;

/// The hibernate cookie is a flag stored at a known location on disk. The early
/// init scripts use this flag to determine whether or not to mount the stateful
/// partition in snapshot mode for resume, or normal read/write mode for a
/// traditional fresh boot. Normally this sort of cookie would be stored as a
/// regular file in the stateful partition itself. But we can't exactly do that
/// because this is the indicator used to determine _how_ to mount the RW
/// file systems.
///
/// This implementation currently stores the flag as a well-known string inside
/// the leftover space at the end of the sector containing the GPT header. This
/// space is ideal because its location is fixed, it's not manipulated in normal
/// circumstances, and the GPT header format is unlikely to change and start
/// using this space.
struct HibernateCookie {
    blockdev: File,
    buffer: MmapBuffer,
}

/// Define the size of the region we update.
const HIBERNATE_COOKIE_READ_SIZE: usize = 0x400;
const HIBERNATE_COOKIE_WRITE_SIZE: usize = 0x400;
/// Define the magic value the GPT stamps down, which we will use to verify
/// we're writing to an area that we expect. If somehow the world shifted out
/// from under us, this could prevent us from silently corrupting data.
const GPT_MAGIC_OFFSET: usize = 0x200;
const GPT_MAGIC: u64 = 0x5452415020494645; // 'EFI PART'

/// The beginning of the disk starts with a protective MBR, followed by a sector
/// just for the GPT header. The GPT header is quite small and doesn't use its
/// whole sector. Define the offset towards the end of the region where the
/// cookie will be written.
const HIBERNATE_MAGIC_OFFSET: usize = 0x3E0;
/// Define the magic token we write to indicate a valid hibernate partition.
/// This is both big (as in bigger than a single bit), and points the finger at
/// an obvious culprit, in the case this does end up unintentionally writing
/// over important data. This is made arbitrarily, but intentionally, to be 16
/// bytes.
const HIBERNATE_MAGIC: &[u8] = b"HibernateCookie!";
/// Define a known "not valid" value as well. This is treated identically to
/// anything else that is invalid, but again could serve as a more useful
/// breadcrumb to someone debugging than 16 vanilla zeroes.
const HIBERNATE_MAGIC_POISON: &[u8] = b"HibernateInvalid";
/// Define the size of the magic token.
const HIBERNATE_MAGIC_SIZE: usize = 16;

impl HibernateCookie {
    /// Create a new HibernateCookie structure. This allocates resources but
    /// does not attempt to read or write the disk.
    pub fn new(path: &Path) -> Result<HibernateCookie> {
        let blockdev = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT | libc::O_SYNC)
            .open(path)
            .map_err(|e| HibernateError::OpenFileError(path.display().to_string(), e))?;

        let buffer = MmapBuffer::new(HIBERNATE_COOKIE_READ_SIZE)?;
        Ok(HibernateCookie { blockdev, buffer })
    }

    /// Read the contents of the disk to determine if the cookie is set or not.
    /// On success, returns a boolean that is true if the hibernate cookie is
    /// set (indicating the on-disk file systems should not be altered).
    pub fn read(&mut self) -> Result<bool> {
        if let Err(e) = self.blockdev.seek(SeekFrom::Start(0)) {
            return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
        }

        let buffer_slice = self.buffer.u8_slice_mut();
        let mut slice_mut = [IoSliceMut::new(
            &mut buffer_slice[..HIBERNATE_COOKIE_READ_SIZE],
        )];
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
        let gpt_sig_offset = GPT_MAGIC_OFFSET;
        let gpt_sig_offset_end = gpt_sig_offset + 8;
        let mut gpt_sig = [0u8; 8];
        let buffer_slice = self.buffer.u8_slice();
        gpt_sig.copy_from_slice(&buffer_slice[gpt_sig_offset..gpt_sig_offset_end]);
        let gpt_sig = u64::from_le_bytes(gpt_sig);
        if gpt_sig != GPT_MAGIC {
            return Err(HibernateError::CookieError(format!(
                "GPT magic not found: {:x?}",
                gpt_sig
            )));
        }

        let magic_start = HIBERNATE_MAGIC_OFFSET;
        let magic_end = magic_start + HIBERNATE_MAGIC_SIZE;
        let equal = buffer_slice[magic_start..magic_end] == *HIBERNATE_MAGIC;
        Ok(equal)
    }

    /// Write the hibernate cookie to disk via a fresh read modify write
    /// operation. The valid parameter indicates whether to write a valid
    /// hibernate cookie (true, indicating on-disk file systems should be
    /// altered), or poison value (false, indicating no impending hibernate
    /// resume, file systems can be mounted RW).
    pub fn write(&mut self, valid: bool) -> Result<()> {
        let existing = self.read()?;
        if let Err(e) = self.blockdev.seek(SeekFrom::Start(0)) {
            return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
        }

        if valid == existing {
            return Ok(());
        }

        let magic_start = HIBERNATE_MAGIC_OFFSET;
        let magic_end = magic_start + HIBERNATE_MAGIC_SIZE;
        let cookie = match valid {
            true => HIBERNATE_MAGIC,
            false => HIBERNATE_MAGIC_POISON,
        };

        let buffer_slice = self.buffer.u8_slice_mut();
        buffer_slice[magic_start..magic_end].copy_from_slice(cookie);
        let end = HIBERNATE_COOKIE_WRITE_SIZE;
        let slice = [IoSlice::new(&buffer_slice[..end])];
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

/// Public function to read the hibernate cookie and return whether or not it is
/// set. The optional path parameter contains the path to the disk to examine.
/// If not supplied, the boot disk will be examined.
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

/// Public function to set the hibernate cookie value. The valid parameter, if
/// true, indicates that upon the next boot file systems should not be altered
/// on disk, since there's a valid resume image. The optional path parameter
/// contains the path to the disk to examine.
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
