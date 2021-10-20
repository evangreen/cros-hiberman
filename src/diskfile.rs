// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement support for accessing file contents directly via the underlying block device.

use crate::fiemap::{Fiemap, FiemapExtent};
use crate::hiberutil::{get_page_size, path_to_stateful_part, HibernateError, Result};
use crate::mmapbuf::MmapBuffer;
use crate::{debug, error};
use std::fs::{File, OpenOptions};
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;

pub struct BouncedDiskFile {
    disk_file: DiskFile,
    buffer: MmapBuffer,
}

impl BouncedDiskFile {
    pub fn new(fs_file: &mut File, block_file: Option<File>) -> Result<BouncedDiskFile> {
        let page_size = get_page_size();
        Ok(BouncedDiskFile {
            disk_file: DiskFile::new(fs_file, block_file)?,
            buffer: MmapBuffer::new(page_size)?,
        })
    }

    pub fn set_logging(&mut self, enable: bool) {
        self.disk_file.set_logging(enable)
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.disk_file.sync_all()
    }

    pub fn rewind(&mut self) -> Result<()> {
        self.disk_file.rewind()
    }
}

impl Read for BouncedDiskFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut offset = 0usize;
        let length = buf.len();
        while offset < length {
            let mut size_this_round = self.buffer.len();
            if size_this_round > (length - offset) {
                size_this_round = length - offset;
            }

            // Read into the aligned buffer.
            let src_end = size_this_round;
            let buffer_slice = self.buffer.u8_slice_mut();
            let mut slice = [IoSliceMut::new(&mut buffer_slice[..src_end])];
            let bytes_done = self.disk_file.read_vectored(&mut slice)?;
            if bytes_done == 0 {
                break;
            }

            // Copy into the caller's buffer.
            let dst_end = offset + bytes_done;
            buf[offset..dst_end].copy_from_slice(&buffer_slice[..bytes_done]);
            offset += bytes_done;
        }

        Ok(offset)
    }
}

impl Write for BouncedDiskFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0usize;
        let length = buf.len();
        while offset < length {
            let mut size_this_round = self.buffer.len();
            if size_this_round > (length - offset) {
                size_this_round = length - offset;
            }

            // Copy into the aligned buffer.
            let src_end = offset + size_this_round;
            let buffer_slice = self.buffer.u8_slice_mut();
            buffer_slice[..size_this_round].copy_from_slice(&buf[offset..src_end]);

            // Do the write.
            let slice = [IoSlice::new(&buffer_slice[..size_this_round])];
            let bytes_done = self.disk_file.write_vectored(&slice)?;
            if bytes_done == 0 {
                break;
            }

            offset += bytes_done;
        }

        Ok(offset)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.disk_file.flush()
    }
}

impl Seek for BouncedDiskFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.disk_file.seek(pos)
    }
}

// A DiskFile can take in a preallocated file and read or write to it
// by accessing the file blocks on disk directly. Operations are not buffered.
pub struct DiskFile {
    fiemap: Fiemap,
    blockdev: File,
    current_position: u64,
    current_extent: FiemapExtent,
    logging: bool,
}

impl DiskFile {
    pub fn new(fs_file: &mut File, block_file: Option<File>) -> Result<DiskFile> {
        let fiemap = Fiemap::new(fs_file)?;
        let blockdev;
        match block_file {
            None => {
                let blockdev_path = path_to_stateful_part()?;
                debug!("Found hibernate block device: {}", blockdev_path);
                blockdev = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_DIRECT)
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
                logging: true,
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

    pub fn set_logging(&mut self, enable: bool) {
        self.logging = enable;
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.blockdev.sync_all()
    }

    pub fn rewind(&mut self) -> Result<()> {
        match self.seek(SeekFrom::Start(0)) {
            Ok(_) => Ok(()),
            Err(e) => Err(HibernateError::FileIoError("Failed to seek".to_string(), e))
        }
    }

    fn current_position_valid(&self) -> bool {
        let start = self.current_extent.fe_logical;
        let end = start + self.current_extent.fe_length;
        (self.current_position >= start) && (self.current_position < end)
    }
}

impl Drop for DiskFile {
    fn drop(&mut self) {
        if self.logging {
            debug!(
                "Dropping {} MB DiskFile",
                self.fiemap.file_size / 1024 / 1024
            );
        }

        if let Err(e) = self.sync_all() {
            if self.logging {
                error!("Error syncing DiskFile: {}", e);
            }
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
            let bytes_done = self.blockdev.read_vectored(&mut slice)?;
            if bytes_done != this_io_length {
                if self.logging {
                    error!(
                        "DiskFile only did {:x?}/{:x?} I/O",
                        bytes_done, this_io_length
                    );
                }
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
            let bytes_done = self.blockdev.write_vectored(&slice)?;
            if bytes_done != this_io_length {
                if self.logging {
                    error!(
                        "DiskFile only wrote {:x?}/{:x?} I/O",
                        bytes_done, this_io_length
                    );
                }
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
        if self.logging {
            debug!("Seeking to {:x}", block_offset);
        }

        self.blockdev.seek(SeekFrom::Start(block_offset))
    }
}
