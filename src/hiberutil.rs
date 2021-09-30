// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement common functions and definitions used throughout the app and library.

use crate::{error, warn};
use std::fs::File;
use std::io::{prelude::*, BufReader};
use thiserror::Error as ThisError;

// Define the mount location where the hibernate data is located.
pub static HIBERNATE_MOUNT_ROOT: &str = "/mnt/stateful_partition";
// Define the alignment needed for direct I/O.
pub static DIRECT_IO_ALIGNMENT: usize = 0x1000;

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
    /// Failed to find the stateful mount.
    #[error("Failed to find the stateful mount")]
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
pub fn path_to_stateful_part() -> Result<String> {
    let mounts_file = match File::open("/proc/mounts") {
        Ok(f) => f,
        Err(e) => return Err(HibernateError::OpenFileError("/proc/mounts".to_string(), e)),
    };

    let reader = BufReader::new(mounts_file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => {
                return Err(HibernateError::RootdevError(
                    "Failed to get line".to_string(),
                ))
            }
        };

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            warn!("Found unexpected line in /proc/mounts: {}", line);
            continue;
        }

        if fields[1] == HIBERNATE_MOUNT_ROOT {
            return Ok(fields[0].to_string());
        }
    }

    return Err(HibernateError::RootdevError(format!(
        "No mount found for {}",
        HIBERNATE_MOUNT_ROOT
    )));
}

pub fn path_to_stateful_block() -> Result<String> {
    let part_path = path_to_stateful_part()?;
    if !part_path.ends_with("p1") {
        return Err(HibernateError::RootdevError(format!(
            "Partition did not end in p1: {}",
            part_path
        )));
    }

    let end = part_path.len() - 2;
    return Ok(String::from(&part_path[..end]));
}
