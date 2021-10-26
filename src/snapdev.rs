// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement snapshot device functionality.

use crate::hiberutil::{HibernateError, Result};
use libc::{self, c_int, c_ulong, c_void, loff_t};
use std::fs::{metadata, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

const SNAPSHOT_PATH: &str = "/dev/snapshot";

// Define snapshot device ioctl numbers.
const SNAPSHOT_FREEZE: c_ulong = 0x3301;
const SNAPSHOT_UNFREEZE: c_ulong = 0x3302;
const SNAPSHOT_ATOMIC_RESTORE: c_ulong = 0x3304;
const SNAPSHOT_GET_IMAGE_SIZE: c_ulong = 0x8008330e;
const SNAPSHOT_PLATFORM_SUPPORT: c_ulong = 0x330f;
const SNAPSHOT_POWER_OFF: c_ulong = 0x3310;
const SNAPSHOT_CREATE_IMAGE: c_ulong = 0x40043311;

pub struct SnapshotDevice {
    pub file: File,
}

impl SnapshotDevice {
    pub fn new(open_for_write: bool) -> Result<SnapshotDevice> {
        if !Path::new(SNAPSHOT_PATH).exists() {
            return Err(HibernateError::SnapshotError(format!(
                "Snapshot device {} does not exist",
                SNAPSHOT_PATH
            )));
        }

        let snapshot_meta = match metadata(SNAPSHOT_PATH) {
            Ok(f) => f,
            Err(e) => return Err(HibernateError::OpenFileError(SNAPSHOT_PATH.to_string(), e)),
        };

        if !snapshot_meta.file_type().is_char_device() {
            return Err(HibernateError::SnapshotError(format!(
                "Snapshot device {} is not a character device",
                SNAPSHOT_PATH
            )));
        }

        let file = match OpenOptions::new()
            .read(!open_for_write)
            .write(open_for_write)
            .open(SNAPSHOT_PATH)
        {
            Ok(f) => f,
            Err(e) => return Err(HibernateError::OpenFileError(SNAPSHOT_PATH.to_string(), e)),
        };

        Ok(SnapshotDevice { file })
    }

    // Freeze userspace
    pub fn freeze_userspace(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_FREEZE, "FREEZE")
    }

    // Unfreeze userspace
    pub fn unfreeze_userspace(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_UNFREEZE, "UNFREEZE")
    }

    // Asks the kernel to create its hibernate snapshot. Returns a boolean
    // indicating whether this process is exeuting in suspend (true) or not
    // (false). Like setjmp(), this function effectively returns twice: once
    // after the snapshot image is created (true), and this is also where we
    // restart execution from when the hibernated image is restored (false).
    pub fn atomic_snapshot(&mut self) -> Result<bool> {
        let mut in_suspend: c_int = 0;
        self.ioctl(
            SNAPSHOT_CREATE_IMAGE,
            "CREATE_IMAGE",
            &mut in_suspend as *mut c_int as *mut c_void,
        )?;
        Ok(in_suspend != 0)
    }

    // Restore, jumping into the fully loaded resume image. On success, this
    // does not return, as it launches into the resumed image.
    pub fn atomic_restore(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_ATOMIC_RESTORE, "ATOMIC_RESTORE")
    }

    // Returns the size of the recently snapshotted hibernate image in bytes.
    pub fn get_image_size(&mut self) -> Result<loff_t> {
        let mut image_size: loff_t = 0;
        self.ioctl(
            SNAPSHOT_GET_IMAGE_SIZE,
            "GET_IMAGE_SIZE",
            &mut image_size as *mut loff_t as *mut c_void,
        )?;
        Ok(image_size)
    }

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

    pub fn power_off(&mut self) -> Result<()> {
        self.simple_ioctl(SNAPSHOT_POWER_OFF, "POWER_OFF")
    }

    // Helper function to send an ioctl with no parameter and return a result.
    fn simple_ioctl(&mut self, ioctl: c_ulong, name: &str) -> Result<()> {
        self.ioctl(ioctl, name, 0 as *mut c_void)
    }

    // Helper function to send an ioctl and return a Result
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
