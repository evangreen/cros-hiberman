// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement snapshot device functionality.

use std::fs::{metadata, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use libc::{self, c_int, c_ulong, c_void, loff_t};

use crate::hiberutil::{HibernateError, Result};

const SNAPSHOT_PATH: &str = "/dev/snapshot";

// Define snapshot device ioctl numbers.
const SNAPSHOT_FREEZE: c_ulong = 0x3301;
const SNAPSHOT_UNFREEZE: c_ulong = 0x3302;
const SNAPSHOT_ATOMIC_RESTORE: c_ulong = 0x3304;
const SNAPSHOT_GET_IMAGE_SIZE: c_ulong = 0x8008330e;
const SNAPSHOT_PLATFORM_SUPPORT: c_ulong = 0x330f;
const SNAPSHOT_POWER_OFF: c_ulong = 0x3310;
const SNAPSHOT_CREATE_IMAGE: c_ulong = 0x40043311;

/// The SnapshotDevice is mostly a group of method functions that send ioctls to
/// an open snapshot device file descriptor.
pub struct SnapshotDevice {
    pub file: File,
}

impl SnapshotDevice {
    /// Open the snapshot device and return a new object.
    pub fn new(open_for_write: bool) -> Result<SnapshotDevice> {
        if !Path::new(SNAPSHOT_PATH).exists() {
            return Err(HibernateError::SnapshotError(format!(
                "Snapshot device {} does not exist",
                SNAPSHOT_PATH
            )));
        }

        let snapshot_meta = metadata(SNAPSHOT_PATH)
            .map_err(|e| HibernateError::OpenFileError(SNAPSHOT_PATH.to_string(), e))?;
        if !snapshot_meta.file_type().is_char_device() {
            return Err(HibernateError::SnapshotError(format!(
                "Snapshot device {} is not a character device",
                SNAPSHOT_PATH
            )));
        }

        let file = OpenOptions::new()
            .read(!open_for_write)
            .write(open_for_write)
            .open(SNAPSHOT_PATH)
            .map_err(|e| HibernateError::OpenFileError(SNAPSHOT_PATH.to_string(), e))?;

        Ok(SnapshotDevice { file })
    }

    /// Freeze userspace, stopping all userspace processes except this one.
    pub fn freeze_userspace(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_FREEZE, "FREEZE")
    }

    /// Unfreeze userspace, resuming all other previously frozen userspace
    /// processes.
    pub fn unfreeze_userspace(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_UNFREEZE, "UNFREEZE")
    }

    /// Ask the kernel to create its hibernate snapshot. Returns a boolean
    /// indicating whether this process is executing in suspend (true) or resume
    /// (false). Like setjmp(), this function effectively returns twice: once
    /// after the snapshot image is created (true), and again when the
    /// hibernated image is restored (false).
    pub fn atomic_snapshot(&mut self) -> Result<bool> {
        let mut in_suspend: c_int = 0;
        self.ioctl(
            SNAPSHOT_CREATE_IMAGE,
            "CREATE_IMAGE",
            &mut in_suspend as *mut c_int as *mut c_void,
        )?;
        Ok(in_suspend != 0)
    }

    /// Jump into the fully loaded resume image. On success, this does not
    /// return, as it launches into the resumed image.
    pub fn atomic_restore(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_ATOMIC_RESTORE, "ATOMIC_RESTORE")
    }

    /// Return the size of the recently snapshotted hibernate image in bytes.
    pub fn get_image_size(&mut self) -> Result<loff_t> {
        let mut image_size: loff_t = 0;
        self.ioctl(
            SNAPSHOT_GET_IMAGE_SIZE,
            "GET_IMAGE_SIZE",
            &mut image_size as *mut loff_t as *mut c_void,
        )?;
        Ok(image_size)
    }

    /// Indicate to the kernel whether or not to power down into "platform" mode
    /// (which I believe means S4).
    pub fn set_platform_mode(&mut self, use_platform_mode: bool) -> Result<()> {
        let mut move_param: c_int = use_platform_mode as c_int;
        // Send the parameter down as a mutable pointer, even though the ioctl
        // will not modify it.
        self.ioctl(
            SNAPSHOT_PLATFORM_SUPPORT,
            "PLATFORM_SUPPORT",
            &mut move_param as *mut c_int as *mut c_void,
        )
    }

    /// Power down the system.
    pub fn power_off(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_POWER_OFF, "POWER_OFF")
    }

    /// Helper function to send an ioctl with no parameter and return a result.
    fn simple_ioctl(&mut self, ioctl: c_ulong, name: &str) -> Result<()> {
        self.ioctl(ioctl, name, std::ptr::null_mut::<c_void>())
    }

    /// Helper function to send an ioctl and return a Result
    fn ioctl(&mut self, ioctl: c_ulong, name: &str, param: *mut c_void) -> Result<()> {
        let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), ioctl, param) };
        if rc < 0 {
            return Err(HibernateError::SnapshotIoctlError(
                name.to_string(),
                sys_util::Error::last(),
            ));
        }

        Ok(())
    }
}
