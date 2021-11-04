// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement common functions and definitions used throughout the app and library.

use std::process::Command;
use thiserror::Error as ThisError;
use crate::{error, warn};

/// Define the number of pages in a larger chunk used to read and write the
/// hibernate data file.
pub const BUFFER_PAGES: usize = 32;

#[derive(Debug, ThisError)]
pub enum HibernateError {
    /// Cookie error
    #[error("Cookie error: {0}")]
    CookieError(String),
    /// Failed to create the hibernate context directory.
    #[error("Failed to create directory: {0}: {1}")]
    CreateDirectoryError(String, std::io::Error),
    /// Dbus error
    #[error("Dbus error: {0}")]
    DbusError(String),
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
    /// First data byte mismatch
    #[error("First data byte mismatch")]
    FirstDataByteMismatch(),
    /// Header content hash mismatch
    #[error("Header content hash mismatch")]
    HeaderContentHashMismatch(),
    /// Header content length mismatch
    #[error("Header content length mismatch")]
    HeaderContentLengthMismatch(),
    /// Invalid fiemap
    #[error("Invalid fiemap: {0}")]
    InvalidFiemapError(String),
    /// Image unencrypted
    #[error("Image unencrypted")]
    ImageUnencryptedError(),
    /// Key manager error
    #[error("Key manager error: {0}")]
    KeyManagerError(String),
    /// Logger uninitialized.
    #[error("Logger uninitialized")]
    LoggerUninitialized(),
    /// Metadata error
    #[error("Metadata error: {0}")]
    MetadataError(String),
    /// Failed to lock process memory.
    #[error("Failed to mlockall: {0}")]
    MlockallError(sys_util::Error),
    /// Mmap error.
    #[error("mmap error: {0}")]
    MmapError(sys_util::Error),
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

/// Options taken from the command line affecting hibernate.
#[derive(Default)]
pub struct HibernateOptions {
    pub dry_run: bool,
    pub unencrypted: bool,
    pub test_keys: bool,
}

/// Options taken from the command line affecting resume.
#[derive(Default)]
pub struct ResumeOptions {
    pub dry_run: bool,
    pub unencrypted: bool,
    pub test_keys: bool,
    pub no_preloader: bool,
}

/// Convert anything to a u8 slice.
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

/// Get the page size on this system.
pub fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Get the amount of free memory (in pages) on this system.
pub fn get_available_pages() -> usize {
    unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) as usize }
}

/// Get the total amount of memory (in pages) on this system.
pub fn get_total_memory_pages() -> usize {
    let pagecount = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) as usize };
    if pagecount == 0 {
        warn!(
            "Failed to get total memory (got {}). Assuming 4GB.",
            pagecount
        );
        return 1024 * 1024 / get_page_size() * 1024 * 4;
    }

    pagecount
}

/// Return the underlying partition device the hibernate files reside on.
/// Note: this still needs to return the real partition, even if stateful
/// is mounted on a dm-snapshot. Otherwise, resume activities won't work
/// across the transition.
pub fn path_to_stateful_part() -> Result<String> {
    let rootdev = path_to_stateful_block()?;
    Ok(format!("{}p1", rootdev))
}

/// Determine the path to the block device containing the stateful partition.
/// Farm this out to rootdev to keep the magic in one place.
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

/// Lock all present and future memory belonging to this process, preventing it
/// from being paged out.
pub fn lock_process_memory() -> Result<()> {
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };

    if rc < 0 {
        return Err(HibernateError::MlockallError(sys_util::Error::last()));
    }

    Ok(())
}

/// Unlock memory belonging to this process, allowing it to be paged out once
/// more.
pub fn unlock_process_memory() {
    unsafe {
        libc::munlockall();
    };
}
