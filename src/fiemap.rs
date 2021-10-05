// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement fiemap support, which can tell you the underlying disk extents backing a file.

use crate::hiberutil::{any_as_u8_slice, HibernateError, Result};
use crate::{debug, error};
use libc::{c_ulong, c_void};
use std::fs::File;
use std::mem;
use std::os::unix::io::AsRawFd;

static FS_IOC_FIEMAP: c_ulong = 0xc020660b;

// The C_Fiemap structure's format is mandated by the FS_IOC_FIEMAP ioctl.
#[repr(C)]
struct C_Fiemap {
    fm_start: u64,
    fm_length: u64,
    fm_flags: u32,
    fm_mapped_extents: u32,
    fm_extent_count: u32,
    fm_reserved: u32,
}

// The FiemapExtent structure's format is mandated by the FS_IOC_FIEMAP ioctl.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FiemapExtent {
    pub fe_logical: u64,
    pub fe_physical: u64,
    pub fe_length: u64,
    fe_reserved64: [u64; 2],
    pub fe_flags: u32,
    fe_reserved: [u32; 3],
}

pub struct Fiemap {
    pub file_size: u64,
    pub extents: Vec<FiemapExtent>,
}

// Sync data before creating the extent map.
static FIEMAP_FLAG_SYNC: u32 = 0x1;
// Map extended attribute tree.
//static FIEMAP_FLAG_XATTR: u32 = 0x2;

// The last extent in a file.
//static FIEMAP_EXTENT_LAST: u32 = 0x1;
// Data location unknown.
static FIEMAP_EXTENT_UNKNOWN: u32 = 0x2;
// Location still pending. Also sets FIEMAP_EXTENT_UNKNOWN.
static FIEMAP_EXTENT_DELALLOC: u32 = 0x4;
// Data can not be read while the file system is unmounted.
static FIEMAP_EXTENT_ENCODED: u32 = 0x8;
// Data is encrypted. Also sets EXTENT_NO_BYPASS.
static FIEMAP_EXTENT_DATA_ENCRYPTED: u32 = 0x80;
// Extent offsets may not be block aligned.
static FIEMAP_EXTENT_ALIGNED: u32 = 0x100;
// Data is mixed with metadata. Sets FIEMAP_EXTENT_NOT_ALIGNED.
static FIEMAP_EXTENT_INLINE: u32 = 0x200;
// Multiple files in a block. Sets FIEMAP_EXTENT_NOT_ALIGNED.
static FIEMAP_EXTENT_TAIL: u32 = 0x400;
// Space is allocated, but no data is written.
//static FIEMAP_EXTENT_UNWRITTEN: u32 = 0x800;
// File does not natively support extents. Result merged for efficiency.
//static FIEMAP_EXTENT_MERGED: u32 = 0x1000;
// Space shared with other files.
static FIEMAP_EXTENT_SHARED: u32 = 0x2000;

// Define the mask of flags that would be bad to see on a file you plan on
// operating on directly.
static FIEMAP_NO_RAW_ACCESS_FLAGS: u32 = FIEMAP_EXTENT_UNKNOWN
    | FIEMAP_EXTENT_DELALLOC
    | FIEMAP_EXTENT_ENCODED
    | FIEMAP_EXTENT_DATA_ENCRYPTED
    | FIEMAP_EXTENT_ALIGNED
    | FIEMAP_EXTENT_INLINE
    | FIEMAP_EXTENT_TAIL
    | FIEMAP_EXTENT_SHARED;

impl Fiemap {
    pub fn new(source_file: &mut File) -> Result<Fiemap> {
        let file_size = source_file.metadata().unwrap().len();
        let extent_count = Fiemap::get_extent_count(source_file, 0, file_size, FIEMAP_FLAG_SYNC)?;
        let proto_extent = FiemapExtent {
            fe_logical: 0,
            fe_physical: 0,
            fe_length: 0,
            fe_reserved64: [0u64, 0u64],
            fe_flags: 0,
            fe_reserved: [0u32; 3],
        };

        let mut extents = vec![proto_extent; extent_count as usize];
        Fiemap::get_extents(source_file, 0, file_size, FIEMAP_FLAG_SYNC, &mut extents)?;
        debug!("File has {} extents:", extents.len());
        for extent in &extents {
            debug!(
                "logical {:x} physical {:x} len {:x} flags {:x}",
                extent.fe_logical, extent.fe_physical, extent.fe_length, extent.fe_flags
            );
            // If the extent has flags that wouldn't go well with direct access, report that
            // now and fail. "Unwritten" is acceptable if the file is to be both written and
            // read from underneath the file system.
            if (extent.fe_flags & FIEMAP_NO_RAW_ACCESS_FLAGS) != 0 {
                error!("File has bad flags {:x} for direct access. Extent logical {:x} physical {:x} len {:x}", extent.fe_flags, extent.fe_logical, extent.fe_physical, extent.fe_length);
                return Err(HibernateError::InvalidFiemapError(format!(
                    "Fiemap extent has unexpected flags {:x}",
                    extent.fe_flags
                )));
            }
        }

        Ok(Fiemap { file_size, extents })
    }

    pub fn extent_for_offset(&self, offset: u64) -> Option<&FiemapExtent> {
        // Binary search would be faster here, but it's not clear if it's worth that
        // level of fanciness.
        for extent in &self.extents {
            if (extent.fe_logical <= offset) && ((extent.fe_logical + extent.fe_length) > offset) {
                return Some(extent);
            }
        }

        return None;
    }

    fn get_extent_count(
        source_file: &mut File,
        fm_start: u64,
        fm_length: u64,
        fm_flags: u32,
    ) -> Result<u32> {
        let mut param = C_Fiemap {
            fm_start,
            fm_length,
            fm_flags,
            fm_mapped_extents: 0,
            fm_extent_count: 0,
            fm_reserved: 0,
        };

        let rc = unsafe {
            libc::ioctl(
                source_file.as_raw_fd(),
                FS_IOC_FIEMAP,
                &mut param as *mut C_Fiemap as *mut c_void,
            )
        };

        if rc < 0 {
            return Err(HibernateError::FiemapError(sys_util::Error::last()));
        }

        Ok(param.fm_mapped_extents as u32)
    }

    fn get_extents(
        source_file: &mut File,
        fm_start: u64,
        fm_length: u64,
        fm_flags: u32,
        extents: &mut Vec<FiemapExtent>,
    ) -> Result<()> {
        let fiemap_len = mem::size_of::<C_Fiemap>();
        let extents_len = extents.len() * mem::size_of::<FiemapExtent>();
        let buffer_size = fiemap_len + extents_len;
        let mut fiemap = C_Fiemap {
            fm_start,
            fm_length,
            fm_flags,
            fm_mapped_extents: 0,
            fm_extent_count: extents.len() as u32,
            fm_reserved: 0,
        };

        let mut buffer = vec![0u8; buffer_size];
        unsafe {
            // Copy the fiemap struct into the beginning of the u8 buffer. This is safe
            // because the buffer was allocated to be larger than this struct size.
            buffer[0..fiemap_len].copy_from_slice(any_as_u8_slice(&fiemap));
            // Safe because the ioctl operates on a buffer bounded by the length we just
            // supplied in fm_extent_count of the struct fiemap.
            let rc = libc::ioctl(
                source_file.as_raw_fd(),
                FS_IOC_FIEMAP,
                buffer.as_mut_ptr() as *mut _ as *mut c_void,
            );
            if rc < 0 {
                return Err(HibernateError::FiemapError(sys_util::Error::last()));
            }

            // Verify the ioctl returned the number of extents expected.
            fiemap = std::ptr::read_unaligned(buffer[0..fiemap_len].as_ptr() as *const _);
            if fiemap.fm_mapped_extents as usize != extents.len() {
                return Err(HibernateError::InvalidFiemapError(format!(
                    "Got {} fiemap extents, expected {}",
                    fiemap.fm_mapped_extents,
                    extents.len()
                )));
            }

            // Copy the extents returned from the ioctl out into the vector.
            for i in 0..extents.len() {
                let start = fiemap_len + (i * mem::size_of::<FiemapExtent>());
                let end = start + mem::size_of::<FiemapExtent>();
                // This is safe because the ioctl returned this many fiemap_extents.
                // This copies from the u8 buffer back into safe (aligned) world.
                extents[i] = std::ptr::read_unaligned(buffer[start..end].as_ptr() as *const _);
            }
        }

        Ok(())
    }
}