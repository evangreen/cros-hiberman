// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement sysfs save/restore functionality.

use crate::hiberutil::{HibernateError, Result};
use crate::{debug, warn};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

const SWAPPINESS_PATH: &str = "/proc/sys/vm/swappiness";

pub struct Swappiness {
    file: File,
    swappiness: i32,
}

impl Swappiness {
    // Create a new Swappiness object, which reads and saves the original value.
    // When this object is dropped, the value read here will be restored.
    pub fn new() -> Result<Self> {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(SWAPPINESS_PATH)
        {
            Ok(f) => f,
            Err(e) => {
                return Err(HibernateError::OpenFileError(
                    SWAPPINESS_PATH.to_string(),
                    e,
                ))
            }
        };

        let swappiness = Self::read_swappiness(&mut file)?;
        debug!("Saved original swappiness: {}", swappiness);
        Ok(Self { file, swappiness })
    }

    pub fn set_swappiness(&mut self, value: i32) -> Result<()> {
        if let Err(e) = self.file.seek(SeekFrom::Start(0)) {
            return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
        }

        match write!(self.file, "{}\n", value) {
            Err(e) => Err(HibernateError::FileIoError(
                "Failed to write".to_string(),
                e,
            )),
            Ok(_) => Ok(()),
        }
    }

    fn read_swappiness(file: &mut File) -> Result<i32> {
        let mut s = String::with_capacity(10);
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
        }

        if let Err(e) = file.read_to_string(&mut s) {
            return Err(HibernateError::FileIoError("Failed to read".to_string(), e));
        }

        match s.trim().parse::<i32>() {
            Err(_) => Err(HibernateError::SwappinessError(format!(
                "Unexpected value: {}",
                s
            ))),
            Ok(v) => Ok(v),
        }
    }
}

impl Drop for Swappiness {
    fn drop(&mut self) {
        debug!("Restoring swappiness to {}", self.swappiness);
        match self.set_swappiness(self.swappiness) {
            Err(e) => warn!("Failed to restore swappiness: {}", e),
            Ok(_) => (),
        };
    }
}
