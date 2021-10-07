// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement support for managing hibernate metadata.

use crate::diskfile::BouncedDiskFile;
use crate::hiberutil::{any_as_u8_slice, HibernateError, Result};
use std::fs::File;
use std::io::{IoSliceMut, Read, Write};

// Magic value used to recognize a hibernate metadata struct.
const HIBERNATE_META_MAGIC: u64 = 0x6174654D72626948;
// Version of the structure contents. Bump this up whenever the
// structure changes.
const HIBERNATE_META_VERSION: u32 = 1;

// Define hibernate metadata flags.
// This flag is set if the hibernate image is valid and ready to be resumed to.
pub const HIBERNATE_META_FLAG_VALID: u32 = 0x00000001;

// This flag is set if the image has already been resumed once. When this flag
// is set the VALID flag is cleared.
pub const HIBERNATE_META_FLAG_RESUMED: u32 = 0x00000002;

// This flag is set if the image has already been resumed into, but the resume
// attempt failed. The RESUMED flag will also be set.
pub const HIBERNATE_META_FLAG_RESUME_FAILED: u32 = 0x00000004;

// This flag is set if the image is encrypted.
pub const HIBERNATE_META_FLAG_ENCRYPTED: u32 = 0x00000008;

// Define the mask of all valid flags.
pub const HIBERNATE_META_VALID_FLAGS: u32 = HIBERNATE_META_FLAG_VALID
    | HIBERNATE_META_FLAG_RESUMED
    | HIBERNATE_META_FLAG_RESUME_FAILED
    | HIBERNATE_META_FLAG_ENCRYPTED;

// Define the size of the hibernate data symmetric encryption key.
pub const HIBERNATE_DATA_KEY_SIZE: usize = 16;
pub const HIBERNATE_DATA_IV_SIZE: usize = HIBERNATE_DATA_KEY_SIZE;

// Define the structure of the hibernate metadata, which is written out to disk.
// Use repr(C) to ensure a consistent structure layout.
#[repr(C)]
pub struct HibernateMetadata {
    // This must be set to HIBERNATE_META_MAGIC.
    magic: u64,
    // This must be set to HIBERNATE_META_VERSION.
    version: u32,
    // The size of the hibernate image data.
    pub image_size: u64,
    // Flags. See HIBERNATE_META_FLAG_* definitions.
    pub flags: u32,
    // Hibernate symmetric encryption key.
    pub data_key: [u8; HIBERNATE_DATA_KEY_SIZE],
    // Hibernate symmetric encryption IV (chosen randomly).
    pub data_iv: [u8; HIBERNATE_DATA_IV_SIZE],
}

impl HibernateMetadata {
    pub fn new() -> Result<Self> {
        let mut urandom = match File::open("/dev/urandom") {
            Ok(f) => f,
            Err(e) => return Err(HibernateError::OpenFileError("/dev/urandom".to_string(), e)),
        };

        let mut data_key = [0u8; HIBERNATE_DATA_KEY_SIZE];
        let mut slice = [IoSliceMut::new(&mut data_key)];
        let bytes_read = match urandom.read_vectored(&mut slice) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read != HIBERNATE_DATA_KEY_SIZE {
            return Err(HibernateError::IoSizeError(format!(
                "Only read {} of {} bytes",
                bytes_read, HIBERNATE_DATA_KEY_SIZE
            )));
        }

        let mut data_iv = [0u8; HIBERNATE_DATA_IV_SIZE];
        let mut slice = [IoSliceMut::new(&mut data_iv)];
        let bytes_read = match urandom.read_vectored(&mut slice) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read != HIBERNATE_DATA_IV_SIZE {
            return Err(HibernateError::IoSizeError(format!(
                "Only read {} of {} bytes",
                bytes_read, HIBERNATE_DATA_IV_SIZE
            )));
        }

        Ok(Self {
            magic: HIBERNATE_META_MAGIC,
            version: HIBERNATE_META_VERSION,
            image_size: 0,
            flags: 0,
            data_key,
            data_iv,
        })
    }

    pub fn load_from_disk(disk_file: &mut BouncedDiskFile) -> Result<Self> {
        let mut buf = vec![0u8; 4096];
        let mut slice = [IoSliceMut::new(&mut buf)];
        let bytes_read = match disk_file.read_vectored(&mut slice) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read < std::mem::size_of::<HibernateMetadata>() {
            return Err(HibernateError::MetadataError(
                "Read too few bytes".to_string(),
            ));
        }

        // This is safe because the buffer is larger than the structure size, and the types
        // in the struct are all basic.
        let metadata: Self = unsafe {
            std::ptr::read_unaligned(
                buf[0..std::mem::size_of::<HibernateMetadata>()].as_ptr() as *const _
            )
        };

        if metadata.magic != HIBERNATE_META_MAGIC {
            return Err(HibernateError::MetadataError(format!(
                "Invalid metadata magic: {:x?}, expected {:x?}",
                metadata.magic, HIBERNATE_META_MAGIC
            )));
        }

        if metadata.version != HIBERNATE_META_VERSION {
            return Err(HibernateError::MetadataError(format!(
                "Invalid metadata version: {:x?}, expected {:x?}",
                metadata.version, HIBERNATE_META_VERSION
            )));
        }

        if (metadata.flags & !HIBERNATE_META_VALID_FLAGS) != 0 {
            return Err(HibernateError::MetadataError(format!(
                "Invalid flags: {:x?}, valid mask {:x?}",
                metadata.flags, HIBERNATE_META_VALID_FLAGS
            )));
        }

        Ok(metadata)
    }

    pub fn write_to_disk(&self, disk_file: &mut BouncedDiskFile) -> Result<()> {
        let mut buf = vec![0u8; 4096];

        // Check the flags being written in case somebody added a flag and
        // forgot to add it to the valid mask.
        if (self.flags & !HIBERNATE_META_VALID_FLAGS) != 0 {
            return Err(HibernateError::MetadataError(format!(
                "Invalid flags: {:x?}, valid mask {:x?}",
                self.flags, HIBERNATE_META_VALID_FLAGS
            )));
        }

        unsafe {
            // Copy the struct into the beginning of the u8 buffer. This is safe
            // because the buffer was allocated to be larger than this struct size.
            buf[0..std::mem::size_of::<HibernateMetadata>()].copy_from_slice(any_as_u8_slice(self));
        }

        let bytes_written = match disk_file.write(&buf[..]) {
            Ok(s) => s,
            Err(e) => {
                return Err(HibernateError::FileIoError(
                    "Failed to write metadata".to_string(),
                    e,
                ))
            }
        };

        if bytes_written < std::mem::size_of::<HibernateMetadata>() {
            return Err(HibernateError::MetadataError(
                "Read too few bytes".to_string(),
            ));
        }

        Ok(())
    }
}
