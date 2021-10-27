// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement the cat debug command

use crate::files::open_bounced_disk_file;
use crate::hiberutil::{HibernateError, Result};
use crate::warn;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

pub fn cat_disk_file(path_str: &str, is_log: bool) -> Result<()> {
    let path = Path::new(path_str);
    let mut file = open_bounced_disk_file(path)?;
    let mut stdout = std::io::stdout();
    if is_log {
        let mut reader = BufReader::new(file);
        let mut buf = Vec::<u8>::new();
        if let Err(e) = reader.read_until(0, &mut buf) {
            warn!("Failed to read log file: {}", e);
            return Err(HibernateError::FileIoError("Failed to read".to_string(), e));
        }

        if let Err(e) = stdout.write(&buf) {
            return Err(HibernateError::FileIoError(
                "Failed to write".to_string(),
                e,
            ));
        }
    } else {
        let mut buf = vec![0u8; 4096];
        loop {
            let bytes_read = match file.read(&mut buf) {
                Ok(s) => s,
                Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
            };

            if bytes_read == 0 {
                break;
            }

            if let Err(e) = stdout.write(&buf[..bytes_read]) {
                return Err(HibernateError::FileIoError(
                    "Failed to write".to_string(),
                    e,
                ));
            }
        }
    }

    Ok(())
}
