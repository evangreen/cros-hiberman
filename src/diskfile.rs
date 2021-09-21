// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement support for accessing file contents directly via the underlying block device.

use crate::fiemap::{Fiemap, FiemapExtent};
use crate::hiberutil::{HibernateError, Result, HIBERNATE_MOUNT_ROOT};
use std::fs::{File, OpenOptions};
use std::io::{
    prelude::*, BufReader, Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Seek, SeekFrom,
    Write,
};
use sys_util::{debug, error, warn};

// A DiskFile can take in a preallocated file and read or write to it
// by accessing the file blocks on disk directly. Operations are not buffered.
pub struct DiskFile {
    fiemap: Fiemap,
    blockdev: File,
    current_position: u64,
    current_extent: FiemapExtent,
}

impl DiskFile {
    pub fn new(fs_file: &mut File, block_file: Option<File>) -> Result<DiskFile> {
        let fiemap = Fiemap::new(fs_file)?;
        let blockdev;
        match block_file {
            None => {
                let blockdev_path = path_to_bdev()?;
                debug!("Found hibernate block device: {}", blockdev_path);
                blockdev = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&blockdev_path)
                {
                    Ok(f) => f,
                    Err(e) => {
                        return Err(HibernateError::OpenFileError(blockdev_path.to_string(), e))
                    }
                };
            }
            Some(f) => {
                blockdev = f;
            }
        }

        // This is safe because a zeroed extent is valid.
        let mut disk_file = unsafe {
            DiskFile {
                fiemap,
                blockdev,
                current_position: 0,
                current_extent: std::mem::zeroed(),
            }
        };

        // Seek to the start of the file so the current_position is always valid.
        match disk_file.seek(SeekFrom::Start(0)) {
            Ok(_) => Ok(disk_file),
            Err(e) => Err(HibernateError::FileIoError(
                "Failed to do initial seek".to_string(),
                e,
            )),
        }
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.blockdev.sync_all()
    }

    fn current_position_valid(&self) -> bool {
        let start = self.current_extent.fe_logical;
        let end = start + self.current_extent.fe_length;
        (self.current_position >= start) && (self.current_position < end)
    }
}

impl Drop for DiskFile {
    fn drop(&mut self) {
        debug!(
            "Dropping {} MB DiskFile",
            self.fiemap.file_size / 1024 / 1024
        );
        if let Err(e) = self.sync_all() {
            error!("Error syncing DiskFile: {}", e);
        }
    }
}

impl Read for DiskFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut offset = 0usize;
        let length = buf.len();
        while offset < length {
            // There is no extending the file size.
            if self.current_position >= self.fiemap.file_size {
                break;
            }

            // Ensure the block device is seeked to the right position.
            if !self.current_position_valid() {
                self.seek(SeekFrom::Current(0))?;
            }

            // Get the offset within the current extent.
            let delta = self.current_position - self.current_extent.fe_logical;
            // Get the size remaining to be read or written in this extent.
            let extent_remaining = self.current_extent.fe_length - delta;
            // Get the minimum of the remaining input buffer or the remaining extent.
            let mut this_io_length = length - offset;
            if this_io_length as u64 > extent_remaining {
                this_io_length = extent_remaining as usize;
            }

            // Get a slice of the portion of the buffer to be read into, and read from
            // the block device into the slice.
            let end = offset + this_io_length;
            let mut slice = [IoSliceMut::new(&mut buf[offset..end])];
            //debug!("Reading {:x?} bytes @{:x?} {:x?}..{:x?}", this_io_length, self.current_position, offset, end);
            let bytes_done = self.blockdev.read_vectored(&mut slice)?;
            if bytes_done != this_io_length {
                error!(
                    "DiskFile only did {:x?}/{:x?} I/O",
                    bytes_done, this_io_length
                );
            }

            self.current_position += bytes_done as u64;
            offset += bytes_done;
        }

        Ok(offset)
    }
}

impl Write for DiskFile {
    // Write is just a copy of read with the low-level changed.
    // TODO: Figure out how to refactor this. I'm stuck on the difference in mutability
    // of the buffers between write and read.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0usize;
        let length = buf.len();
        while offset < length {
            // There is no extending the file size.
            if self.current_position >= self.fiemap.file_size {
                break;
            }

            // Ensure the block device is seeked to the right position.
            if !self.current_position_valid() {
                self.seek(SeekFrom::Current(0))?;
            }

            // Get the offset within the current extent.
            let delta = self.current_position - self.current_extent.fe_logical;
            // Get the size remaining to be read or written in this extent.
            let extent_remaining = self.current_extent.fe_length - delta;
            // Get the minimum of the remaining input buffer or the remaining extent.
            let mut this_io_length = length - offset;
            if this_io_length as u64 > extent_remaining {
                this_io_length = extent_remaining as usize;
            }

            // Get a slice of the portion of the buffer to be read into, and read from
            // the block device into the slice.
            let end = offset + this_io_length;
            let slice = [IoSlice::new(&buf[offset..end])];
            //debug!("Writing {:x?} bytes @{:x?} {:x?}..{:x?}", this_io_length, self.current_position, offset, end);
            let bytes_done = self.blockdev.write_vectored(&slice)?;
            if bytes_done != this_io_length {
                error!(
                    "DiskFile only wrote {:x?}/{:x?} I/O",
                    bytes_done, this_io_length
                );
            }

            self.current_position += bytes_done as u64;
            offset += bytes_done;
        }

        Ok(offset)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.blockdev.flush()
    }
}

impl Seek for DiskFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let mut pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.fiemap.file_size as i64 + p,
            SeekFrom::Current(p) => self.current_position as i64 + p,
        };

        if pos < 0 {
            return Err(IoError::new(ErrorKind::InvalidInput, "Negative seek"));
        }

        if pos > self.fiemap.file_size as i64 {
            pos = self.fiemap.file_size as i64;
        }

        let pos = pos as u64;
        self.current_extent = match self.fiemap.extent_for_offset(pos) {
            None => {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "No extent for position",
                ))
            }
            Some(e) => *e,
        };

        self.current_position = pos;
        let delta = self.current_position - self.current_extent.fe_logical;
        let block_offset = self.current_extent.fe_physical + delta;
        debug!("Seeking to {:x}", block_offset);
        self.blockdev.seek(SeekFrom::Start(block_offset))
    }
}

// Return the underlying partition device the hibernate files reside on.
fn path_to_bdev() -> Result<String> {
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
