// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement common functions and definitions used throughout the app and library.

use crate::error;
use std::process::Command;
use thiserror::Error as ThisError;

// Define the alignment needed for direct I/O.
pub const DIRECT_IO_ALIGNMENT: usize = 0x1000;

#[derive(Debug, ThisError)]
pub enum HibernateError {
    /// Cookie error
    #[error("Cookie error: {0}")]
    CookieError(String),
    /// Failed to create the hibernate context directory.
    #[error("Failed to create directory: {0}: {1}")]
    CreateDirectoryError(String, std::io::Error),
    /// Failed to do an I/O operation on a file
    #[error("Failed file operation: {0}: {1}")]
    FileIoError(String, std::io::Error),
    /// Failed to sync a file.
    #[error("Failed file sync: {0}: {1}")]
    FileSyncError(String, std::io::Error),
    /// Failed to create or open a file.
    #[error("Failed to open or create file: {0}: {1}")]
    OpenFileError(String, std::io::Error),
    /// Failed to copy the FD for the polling context.
    #[error("Failed to fallocate the file: {0}")]
    FallocateError(sys_util::Error),
    /// Error getting the fiemap
    #[error("Error getting the fiemap: {0}")]
    FiemapError(sys_util::Error),
    /// Failed to get physical memory size.
    #[error("Failed to get the physical memory sizd")]
    GetMemorySizeError(),
    /// Invalid fiemap
    #[error("Invalid fiemap: {0}")]
    InvalidFiemapError(String),
    /// Image unencrypted
    #[error("Image unencrypted")]
    ImageUnencryptedError(),
    /// Logger uninitialized.
    #[error("Logger uninitialized")]
    LoggerUninitialized(),
    /// Metadata error
    #[error("Metadata error: {0}")]
    MetadataError(String),
    /// Failed to lock process memory.
    #[error("Failed to mlockall: {0}")]
    MlockallError(sys_util::Error),
    /// Poisoned
    #[error("Poisoned")]
    PoisonedError(),
    /// I/O size error
    #[error("I/O size error: {0}")]
    IoSizeError(String),
    /// Failed to find the stateful mount.
    #[error("Failed to find the stateful mount: {0}")]
    RootdevError(String),
    /// Snapshot device error.
    #[error("Snapshot device error: {0}")]
    SnapshotError(String),
    /// Snapshot ioctl error.
    #[error("Snapshot ioctl error: {0}: {1}")]
    SnapshotIoctlError(String, sys_util::Error),
    /// Statvfs error
    #[error("Statvfs error: {0}")]
    StatvfsError(sys_util::Error),
    /// Swappiness error
    #[error("Swappiness error: {0}")]
    SwappinessError(String),
}

pub type Result<T> = std::result::Result<T, HibernateError>;

pub struct HibernateOptions {
    pub dry_run: bool,
    pub unencrypted: bool,
}

impl HibernateOptions {
    pub fn new() -> Self {
        HibernateOptions {
            dry_run: false,
            unencrypted: false,
        }
    }
}

pub struct ResumeOptions {
    pub dry_run: bool,
    pub unencrypted: bool,
}

impl ResumeOptions {
    pub fn new() -> Self {
        ResumeOptions {
            dry_run: false,
            unencrypted: false,
        }
    }
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

// Compute the byte offset to start at for the given vector to get a buffer
// aligned to the given size. The alignment must be a power of two, and smaller
// than the buffer.
pub fn buffer_alignment_offset(buf: &Vec<u8>, alignment: usize) -> usize {
    let address = buf.as_ptr() as usize;
    let offset = address & (alignment - 1);
    if offset == 0 {
        return offset;
    }

    return alignment - offset;
}

// Return the underlying partition device the hibernate files reside on.
// Note: this still needs to return the real partition, even if stateful
// is mounted on a dm-snapshot. Otherwise, resume activities won't work
// across the transition.
pub fn path_to_stateful_part() -> Result<String> {
    let rootdev = path_to_stateful_block()?;
    Ok(format!("{}p1", rootdev))
}

pub fn path_to_stateful_block() -> Result<String> {
    let output = match Command::new("/usr/bin/rootdev").arg("-d").output() {
        Ok(o) => o,
        Err(e) => {
            return Err(HibernateError::RootdevError(format!(
                "Failed to get rootdev: {}",
                e
            )))
        }
    };

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
