// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement common functions and definitions used throughout the app and library.

use thiserror::Error as ThisError;

// Define the mount location where the hibernate data is located.
pub static HIBERNATE_MOUNT_ROOT: &str = "/mnt/stateful_partition";

#[derive(Debug, ThisError)]
pub enum HibernateError {
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
    /// Invalid fiemap
    #[error("Invalid fiemap: {0}")]
    InvalidFiemapError(String),
    /// Failed to get physical memory size.
    #[error("Failed to get the physical memory siz")]
    GetMemorySizeError(),
    /// Metadata error
    #[error("Metadata error: {0}")]
    MetadataError(String),
    /// Failed to lock process memory.
    #[error("Failed to mlockall: {0}")]
    MlockallError(sys_util::Error),
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
