// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement sysfs save/restore functionality.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::hiberutil::{HibernateError, Result};
use crate::{debug, warn};

const SWAPPINESS_PATH: &str = "/proc/sys/vm/swappiness";

/// This simple object remembers the original value of the swappiness file, so
/// that upon being dropped it can be restored.
pub struct Swappiness {
    file: File,
    swappiness: i32,
}

impl Swappiness {
    /// Create a new Swappiness object, which reads and saves the original value.
    /// When this object is dropped, the value read here will be restored.
    pub fn new() -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(SWAPPINESS_PATH)
            .map_err(|e| HibernateError::OpenFileError(SWAPPINESS_PATH.to_string(), e))?;

        let swappiness = Self::read_swappiness(&mut file)?;
        debug!("Saved original swappiness: {}", swappiness);
        Ok(Self { file, swappiness })
    }

    /// Set the current swappiness value.
    pub fn set_swappiness(&mut self, value: i32) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| HibernateError::FileIoError("Failed to seek".to_string(), e))?;

        writeln!(self.file, "{}", value)
            .map_err(|e| HibernateError::FileIoError("Failed to write".to_string(), e))?;

        Ok(())
    }

    /// Internal helper function to read the current swappiness value.
    fn read_swappiness(file: &mut File) -> Result<i32> {
        let mut s = String::with_capacity(10);
        file.seek(SeekFrom::Start(0))
            .map_err(|e| HibernateError::FileIoError("Failed to seek".to_string(), e))?;
        file.read_to_string(&mut s)
            .map_err(|e| HibernateError::FileIoError("Failed to read".to_string(), e))?;
        s.trim()
            .parse::<i32>()
            .map_err(|_| HibernateError::SwappinessError(format!("Unexpected value: {}", s)))
    }
}

impl Drop for Swappiness {
    fn drop(&mut self) {
        debug!("Restoring swappiness to {}", self.swappiness);
        if let Err(e) = self.set_swappiness(self.swappiness) {
            warn!("Failed to restore swappiness: {}", e);
        }
    }
}
