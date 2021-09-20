// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement hibernate functionality

use libc::{self, c_int, c_ulong, c_void, loff_t};
use std::ffi::CString;
use std::fs::{create_dir, metadata, File, OpenOptions};
use std::io::{
    prelude::*, BufReader, Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Seek, SeekFrom,
    Write,
};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use sys_util::{debug, error, info, warn};
use thiserror::Error as ThisError;

static HIBERNATE_MOUNT_ROOT: &str = "/mnt/stateful_partition";
static HIBERNATE_DIR: &str = "/mnt/stateful_partition/unencrypted/hibernate";
static HIBER_META_NAME: &str = "metadata";
static HIBER_META_SIZE: i64 = 1024 * 1024 * 8;
static HIBER_DATA_NAME: &str = "hiberfile";
static SNAPSHOT_PATH: &str = "/dev/snapshot";
static SWAPPINESS_PATH: &str = "/proc/sys/vm/swappiness";
static SUSPEND_SWAPPINESS: i32 = 100;
// How many pages comprise a single buffer.
static BUFFER_PAGES: usize = 32;
// How should the buffer be aligned.
static BUFFER_ALIGNMENT: usize = 4096;
// How low stateful free space is before we clean up the hiberfile after each
// hibernate.
static LOW_DISK_FREE_THRESHOLD: u64 = 10;

// Define snapshot device ioctl numbers.
static SNAPSHOT_FREEZE: c_ulong = 0x3301;
static SNAPSHOT_ATOMIC_RESTORE: c_ulong = 0x3304;
static SNAPSHOT_GET_IMAGE_SIZE: c_ulong = 0x8008330e;
static SNAPSHOT_PLATFORM_SUPPORT: c_ulong = 0x330f;
static SNAPSHOT_POWER_OFF: c_ulong = 0x3310;
static SNAPSHOT_CREATE_IMAGE: c_ulong = 0x40043311;

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

fn get_fs_stats(path: &Path) -> Result<libc::statvfs> {
    let path_str_c = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut stats: libc::statvfs;

    let rc = unsafe {
        // It's safe to zero out a new struct.
        stats = std::mem::zeroed();
        // It's safe to call this libc function with a struct we made ourselves.
        libc::statvfs(path_str_c.as_ptr(), &mut stats)
    };

    if rc < 0 {
        return Err(HibernateError::StatvfsError(sys_util::Error::last()));
    }

    Ok(stats)
}

fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn get_total_memory_mb() -> Result<u32> {
    let pagesize = get_page_size() as i64;
    let pagecount = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) as i64 };

    debug!("Pagesize {} pagecount {}", pagesize, pagecount);
    if pagecount <= 0 {
        return Err(HibernateError::GetMemorySizeError());
    }

    let mb = pagecount * pagesize / (1024 * 1024);
    if mb > 0xFFFFFFFF {
        Ok(0xFFFFFFFFu32)
    } else {
        Ok(mb as u32)
    }
}

fn preallocate_file(path: &Path, size: i64) -> Result<File> {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return Err(HibernateError::OpenFileError(path.display().to_string(), e)),
    };

    let rc = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, size) as isize };

    if rc < 0 {
        return Err(HibernateError::FallocateError(sys_util::Error::last()));
    }

    Ok(file)
}

fn preallocate_metadata_file() -> Result<DiskFile> {
    let metadata_path = Path::new(HIBERNATE_DIR).join(HIBER_META_NAME);
    let mut meta_file = preallocate_file(&metadata_path, HIBER_META_SIZE)?;
    DiskFile::new(&mut meta_file, None)
}

fn preallocate_hiberfile() -> Result<DiskFile> {
    let hiberfile_path = Path::new(HIBERNATE_DIR).join(HIBER_DATA_NAME);

    // The maximum size of the hiberfile is half of memory, plus a little
    // fudge for rounding.
    let memory_mb = get_total_memory_mb()?;
    let hiberfile_mb = (memory_mb / 2) + 2;
    debug!(
        "System has {} MB of memory, preallocating {} MB hiberfile",
        memory_mb, hiberfile_mb
    );

    let hiber_size = (hiberfile_mb as i64) * 1024 * 1024;
    let mut hiber_file = preallocate_file(&hiberfile_path, hiber_size)?;
    info!("Successfully preallocated {} MB hiberfile", hiberfile_mb);
    DiskFile::new(&mut hiber_file, None)
}

// Open a pre-existing disk file, still with read and write permissions.
fn open_disk_file(path: &Path) -> Result<DiskFile> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) => return Err(HibernateError::OpenFileError(path.display().to_string(), e)),
    };

    DiskFile::new(&mut file, None)
}

// Open a pre-existing hiberfile, still with read and write permissions.
fn open_hiberfile() -> Result<DiskFile> {
    let hiberfile_path = Path::new(HIBERNATE_DIR).join(HIBER_DATA_NAME);
    open_disk_file(&hiberfile_path)
}

// Open a pre-existing hiberfile, still with read and write permissions.
fn open_metafile() -> Result<DiskFile> {
    let hiberfile_path = Path::new(HIBERNATE_DIR).join(HIBER_META_NAME);
    open_disk_file(&hiberfile_path)
}

fn lock_process_memory() -> Result<()> {
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };

    if rc < 0 {
        return Err(HibernateError::MlockallError(sys_util::Error::last()));
    }

    Ok(())
}

fn unlock_process_memory() -> () {
    unsafe {
        libc::munlockall();
    }

    ()
}

struct SwappinessData {
    file: File,
    swappiness: i32,
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

fn write_swappiness(file: &mut File, value: i32) -> Result<()> {
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        return Err(HibernateError::FileIoError("Failed to seek".to_string(), e));
    }

    match write!(file, "{}\n", value) {
        Err(e) => Err(HibernateError::FileIoError(
            "Failed to write".to_string(),
            e,
        )),
        Ok(_) => Ok(()),
    }
}

fn save_swappiness() -> Result<SwappinessData> {
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

    let value = read_swappiness(&mut file)?;
    debug!("Saved original swappiness: {}", value);
    Ok(SwappinessData {
        file,
        swappiness: value,
    })
}

impl Drop for SwappinessData {
    fn drop(&mut self) {
        debug!("Restoring swappiness to {}", self.swappiness);
        match write_swappiness(&mut self.file, self.swappiness) {
            Err(e) => warn!("Failed to restore swappiness: {}", e),
            Ok(_) => (),
        };
    }
}

fn open_snapshot(for_write: bool) -> Result<File> {
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

    match OpenOptions::new()
        .read(!for_write)
        .write(for_write)
        .open(SNAPSHOT_PATH)
    {
        Ok(f) => Ok(f),
        Err(e) => return Err(HibernateError::OpenFileError(SNAPSHOT_PATH.to_string(), e)),
    }
}

fn freeze_userspace(snap_dev: &mut File) -> Result<()> {
    info!("Freezing userspace");
    let rc = unsafe { libc::ioctl(snap_dev.as_raw_fd(), SNAPSHOT_FREEZE, 0) };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            "FREEZE".to_string(),
            sys_util::Error::last(),
        ));
    }

    Ok(())
}

// Asks the kernel to create its hibernate snapshot. Returns a boolean indicating whether this
// process is exeuting in suspend (true) or not (false). Like setjmp(), this function effectively
// returns twice: once after the snapshot image is created (true), and this is also where we
// restart execution from when the hibernated image is restored (false).
fn atomic_snapshot(snap_dev: &mut File) -> Result<bool> {
    let mut in_suspend: c_int = 0;
    let rc = unsafe {
        libc::ioctl(
            snap_dev.as_raw_fd(),
            SNAPSHOT_CREATE_IMAGE,
            &mut in_suspend as *mut c_int as *mut c_void,
        )
    };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            "CREATE_IMAGE".to_string(),
            sys_util::Error::last(),
        ));
    }

    Ok(in_suspend != 0)
}

fn atomic_restore(snap_dev: &mut File) -> Result<()> {
    let rc = unsafe { libc::ioctl(snap_dev.as_raw_fd(), SNAPSHOT_ATOMIC_RESTORE, 0) };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            "RESTORE".to_string(),
            sys_util::Error::last(),
        ));
    }

    Ok(())
}

fn get_image_size(snap_dev: &mut File) -> Result<loff_t> {
    let mut image_size: loff_t = 0;
    let rc = unsafe {
        libc::ioctl(
            snap_dev.as_raw_fd(),
            SNAPSHOT_GET_IMAGE_SIZE,
            &mut image_size as *mut loff_t as *mut c_void,
        )
    };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            "GET_IMAGE_SIZE".to_string(),
            sys_util::Error::last(),
        ));
    }

    Ok(image_size)
}

fn set_platform_mode(snap_dev: &mut File, use_platform_mode: bool) -> Result<()> {
    let move_param: c_int = use_platform_mode as c_int;
    let rc = unsafe {
        libc::ioctl(
            snap_dev.as_raw_fd(),
            SNAPSHOT_PLATFORM_SUPPORT,
            &move_param as *const c_int as *const c_void,
        )
    };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            "PLATFORM_SUPPORT".to_string(),
            sys_util::Error::last(),
        ));
    }

    Ok(())
}

fn snapshot_power_off(snap_dev: &mut File) -> Result<()> {
    let rc = unsafe { libc::ioctl(snap_dev.as_raw_fd(), SNAPSHOT_POWER_OFF, 0) };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            "POWER_OFF".to_string(),
            sys_util::Error::last(),
        ));
    }

    Ok(())
}

// Magic value used to recognize a hibernate metadata struct.
static HIBERNATE_META_MAGIC: u64 = 0x6174654D72626948;
// Version of the structure contents. Bump this up whenever the
// structure changes.
static HIBERNATE_META_VERSION: u32 = 1;

// Define hibernate metadata flags.
// This flag is set if the hibernate image is valid and ready to be resumed to.
static HIBERNATE_META_FLAG_VALID: u32 = 0x00000001;

// This flag is set if the image has already been resumed once. When this flag
// is set the VALID flag is cleared.
static HIBERNATE_META_FLAG_RESUMED: u32 = 0x00000002;

// This flag is set if the image has already been resumed into, but the resume
// attempt failed. The RESUMED flag will also be set.
static HIBERNATE_META_FLAG_RESUME_FAILED: u32 = 0x00000004;

// Define the mask of all valid flags.
static HIBERNATE_META_VALID_FLAGS: u32 =
    HIBERNATE_META_FLAG_VALID | HIBERNATE_META_FLAG_RESUMED | HIBERNATE_META_FLAG_RESUME_FAILED;

// Define the structure of the hibernate metadata, which is written out to disk.
// Use repr(C) to ensure a consistent structure layout.
#[repr(C)]
struct HibernateMetadata {
    // This must be set to HIBERNATE_META_MAGIC.
    magic: u64,
    // This must be set to HIBERNATE_META_VERSION.
    version: u32,
    // The size of the hibernate image data.
    image_size: u64,
    // Flags. See HIBERNATE_META_FLAG_* definitions.
    flags: u32,
}

impl HibernateMetadata {
    fn new() -> Self {
        Self {
            magic: HIBERNATE_META_MAGIC,
            version: HIBERNATE_META_VERSION,
            image_size: 0,
            flags: 0,
        }
    }

    fn load_from_disk(disk_file: &mut DiskFile) -> Result<Self> {
        let mut buf = vec![0u8; 4096];
        let mut slice = [IoSliceMut::new(&mut buf)];
        let bytes_read = match disk_file.read_vectored(&mut slice) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read < std::mem::size_of::<HibernateMetadata>() {
            return Err(HibernateError::MetadataError(
                "Read too few bytes".to_string(),
            ));
        }

        // This is safe because the buffer is larger than the structure size, and the types
        // in the struct are all basic.
        let metadata: Self = unsafe {
            std::ptr::read_unaligned(
                buf[0..std::mem::size_of::<HibernateMetadata>()].as_ptr() as *const _
            )
        };

        if metadata.magic != HIBERNATE_META_MAGIC {
            return Err(HibernateError::MetadataError(format!(
                "Invalid metadata magic: {:x?}, expected {:x?}",
                metadata.magic, HIBERNATE_META_MAGIC
            )));
        }

        if metadata.version != HIBERNATE_META_VERSION {
            return Err(HibernateError::MetadataError(format!(
                "Invalid metadata version: {:x?}, expected {:x?}",
                metadata.version, HIBERNATE_META_VERSION
            )));
        }

        if (metadata.flags & !HIBERNATE_META_VALID_FLAGS) != 0 {
            return Err(HibernateError::MetadataError(format!(
                "Invalid flags: {:x?}, valid mask {:x?}",
                metadata.flags, HIBERNATE_META_VALID_FLAGS
            )));
        }

        Ok(metadata)
    }

    fn write_to_disk(&self, disk_file: &mut DiskFile) -> Result<()> {
        let mut buf = vec![0u8; 4096];

        // Check the flags being written in case somebody added a flag and
        // forgot to add it to the valid mask.
        if (self.flags & !HIBERNATE_META_VALID_FLAGS) != 0 {
            return Err(HibernateError::MetadataError(format!(
                "Invalid flags: {:x?}, valid mask {:x?}",
                self.flags, HIBERNATE_META_VALID_FLAGS
            )));
        }

        unsafe {
            // Copy the struct into the beginning of the u8 buffer. This is safe
            // because the buffer was allocated to be larger than this struct size.
            buf[0..std::mem::size_of::<HibernateMetadata>()].copy_from_slice(any_as_u8_slice(self));
        }

        //let slice = [IoSlice::new(&buf)];
        let bytes_written = match disk_file.write(&buf[..]) {
            Ok(s) => s,
            Err(e) => {
                return Err(HibernateError::FileIoError(
                    "Failed to write metadata".to_string(),
                    e,
                ))
            }
        };

        if bytes_written < std::mem::size_of::<HibernateMetadata>() {
            return Err(HibernateError::MetadataError(
                "Read too few bytes".to_string(),
            ));
        }

        Ok(())
    }
}

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
struct FiemapExtent {
    fe_logical: u64,
    fe_physical: u64,
    fe_length: u64,
    fe_reserved64: [u64; 2],
    fe_flags: u32,
    fe_reserved: [u32; 3],
}

struct Fiemap {
    file_size: u64,
    extents: Vec<FiemapExtent>,
}

// Sync data before creating the extent map.
static FIEMAP_FLAG_SYNC: u32 = 0x1;
// Map extended attribute tree.
static FIEMAP_FLAG_XATTR: u32 = 0x2;

// The last extent in a file.
static FIEMAP_EXTENT_LAST: u32 = 0x1;
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
static FIEMAP_EXTENT_UNWRITTEN: u32 = 0x800;
// File does not natively support extents. Result merged for efficiency.
static FIEMAP_EXTENT_MERGED: u32 = 0x1000;
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

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

impl Fiemap {
    fn new(source_file: &mut File) -> Result<Fiemap> {
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

    fn extent_for_offset(&self, offset: u64) -> Option<&FiemapExtent> {
        // Binary search would be faster here, but it's not clear if it's worth that
        // level of fanciness.
        for extent in &self.extents {
            if (extent.fe_logical <= offset) && ((extent.fe_logical + extent.fe_length) > offset) {
                return Some(extent);
            }
        }

        return None;
    }

    // Return a tuple containing the physical offset of the file for the given logical offset, and the
    // length in bytes it runs for.
    fn physical_for_offset(&self, offset: u64) -> Option<(u64, u64)> {
        let extent = match self.extent_for_offset(offset) {
            None => return None,
            Some(e) => e,
        };

        let delta = offset - extent.fe_logical;
        Some((extent.fe_physical + delta, extent.fe_length - delta))
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

// A DiskFile can take in a preallocated file and read or write to it
// by accessing the file blocks on disk directly. Operations are not buffered.
struct DiskFile {
    fiemap: Fiemap,
    blockdev: File,
    current_position: u64,
    current_extent: FiemapExtent,
}

impl DiskFile {
    fn new(fs_file: &mut File, block_file: Option<File>) -> Result<DiskFile> {
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

        let mut disk_file = DiskFile {
            fiemap,
            blockdev,
            current_position: 0,
            current_extent: FiemapExtent {
                fe_logical: 0,
                fe_physical: 0,
                fe_length: 0,
                fe_reserved64: [0u64; 2],
                fe_flags: 0,
                fe_reserved: [0u32; 3],
            },
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

    fn current_position_valid(&self) -> bool {
        let start = self.current_extent.fe_logical;
        let end = start + self.current_extent.fe_length;
        (self.current_position >= start) && (self.current_position < end)
    }

    fn sync_all(&self) -> std::io::Result<()> {
        self.blockdev.sync_all()
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

struct ImageMover<'a> {
    source_file: &'a mut dyn Read,
    dest_file: &'a mut dyn Write,
    source_size: loff_t,
    bytes_done: loff_t,
    source_chunk: usize,
    dest_chunk: usize,
    buffer_size: usize,
    buffer: Vec<u8>,
    buffer_offset: usize,
    buffer_align: usize,
    percent_reported: u32,
}

// Push data from one location to another in chunks, using an aligned buffer.
impl<'a> ImageMover<'a> {
    fn new(
        source_file: &'a mut dyn Read,
        dest_file: &'a mut dyn Write,
        source_size: loff_t,
        source_chunk: usize,
        dest_chunk: usize,
    ) -> ImageMover<'a> {
        // The buffer size is the max of the source or destination chunk size.
        // Both are expected to be powers of two, which means one is always a multiple
        // of the other.
        let mut buffer_size = source_chunk;
        if buffer_size < dest_chunk {
            buffer_size = dest_chunk;
        }

        let buffer = vec![0u8; buffer_size + BUFFER_ALIGNMENT];
        let address = buffer.as_ptr() as usize;
        let buffer_align = BUFFER_ALIGNMENT - (address & (BUFFER_ALIGNMENT - 1));
        Self {
            source_file,
            dest_file,
            source_size,
            bytes_done: 0,
            source_chunk,
            dest_chunk,
            buffer_size,
            buffer,
            buffer_offset: 0,
            buffer_align,
            percent_reported: 0,
        }
    }

    fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer_offset == 0 {
            return Ok(());
        }

        let mut offset: usize = 0;
        while offset < self.buffer_offset {
            // Copy the remainder of the buffer, capped to the destination chunk size.
            let mut length = self.buffer_offset - offset;
            if length > self.dest_chunk {
                length = self.dest_chunk;
            }

            let start = self.buffer_align + offset;
            let end = start + length;
            let bytes_written = match self.dest_file.write(&self.buffer[start..end]) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Only wrote {}-{}, {}/{}",
                        offset,
                        end - start,
                        self.bytes_done,
                        self.source_size
                    );
                    return Err(HibernateError::FileIoError(
                        "Failed to write".to_string(),
                        e,
                    ));
                }
            };

            offset += bytes_written;
            self.bytes_done += bytes_written as i64;
        }

        let percent_done = (self.bytes_done * 100 / self.source_size) as u32;
        if (percent_done / 10) != (self.percent_reported / 10) {
            debug!(
                "Wrote {}%, {}/{}",
                percent_done, self.bytes_done, self.source_size
            );
            self.percent_reported = percent_done;
        }

        self.buffer_offset = 0;
        Ok(())
    }

    fn move_chunk(&mut self) -> Result<()> {
        // Move the whole rest of the image, capped to the source chunk size,
        // and capped to the remaining buffer space.
        let mut length = self.source_size - self.bytes_done - (self.buffer_offset as i64);
        if length > self.source_chunk as i64 {
            length = self.source_chunk as i64;
        }

        let mut length = length as usize;
        if length > self.buffer_size - self.buffer_offset {
            length = self.buffer_size - self.buffer_offset;
        }

        let start = self.buffer_align + self.buffer_offset;
        let end = start + length;
        let mut slice_mut = [IoSliceMut::new(&mut self.buffer[start..end])];
        let bytes_read = match self.source_file.read_vectored(&mut slice_mut) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read < length {
            warn!(
                "Only Read {}/{}, {}/{}",
                bytes_read, length, self.bytes_done, self.source_size
            );
        }

        self.buffer_offset += bytes_read;
        if self.buffer_offset >= self.buffer_size {
            self.flush_buffer()?;
        }

        Ok(())
    }

    fn move_all(&mut self) -> Result<()> {
        debug!("Moving image");
        while self.bytes_done + (self.buffer_offset as i64) < self.source_size {
            self.move_chunk()?;
        }

        self.flush_buffer()?;
        // let result = match self.dest_file.sync_all() {
        //     Ok(_) => Ok(()),
        //     Err(e) => Err(HibernateError::FileSyncError("Failed to sync".to_string(), e))
        // };

        debug!("Finished moving image");
        //result
        Ok(())
    }
}

fn write_image(
    snap_dev: &mut File,
    hiber_file: &mut DiskFile,
    metadata: &mut HibernateMetadata,
) -> Result<()> {
    let image_size = get_image_size(snap_dev)?;
    let page_size = get_page_size();
    debug!("Hibernate image is {} bytes", image_size);
    let mut writer = ImageMover::new(
        snap_dev,
        hiber_file,
        image_size,
        page_size,
        page_size * BUFFER_PAGES,
    );
    writer.move_all()?;
    info!("Wrote {} MB", image_size / 1024 / 1024);
    metadata.image_size = image_size as u64;
    metadata.flags |= HIBERNATE_META_FLAG_VALID;
    Ok(())
}

fn read_image(
    snap_dev: &mut File,
    hiber_file: &mut DiskFile,
    metadata: &mut HibernateMetadata,
) -> Result<()> {
    let image_size = metadata.image_size;
    debug!("Resume image is {} bytes", image_size);
    let page_size = get_page_size();
    // Move from the image, which can read big chunks, to the snapshot dev, which only writes pages.
    let mut reader = ImageMover::new(
        hiber_file,
        snap_dev,
        image_size as i64,
        page_size * BUFFER_PAGES,
        page_size,
    );
    reader.move_all()?;
    info!("Read {} MB", image_size / 1024 / 1024);
    Ok(())
}

fn suspend_system(mut hiber_file: DiskFile, mut meta_file: DiskFile, dry_run: bool) -> Result<()> {
    let mut metadata = HibernateMetadata::new();
    let mut snap_dev = open_snapshot(false)?;
    freeze_userspace(&mut snap_dev)?;
    set_platform_mode(&mut snap_dev, false)?;
    if atomic_snapshot(&mut snap_dev)? {
        // Suspend path. Everything after this point is invisible to the hibernated kernel.
        write_image(&mut snap_dev, &mut hiber_file, &mut metadata)?;
        drop(hiber_file);
        metadata.write_to_disk(&mut meta_file)?;
        drop(meta_file);
        if dry_run {
            info!("Not powering off due to dry run");
        } else {
            info!("Powering off");
            snapshot_power_off(&mut snap_dev)?;
            error!("Returned from power off");
        }
    } else {
        info!("Resumed from hibernate");
    }

    Ok(())
}

fn delete_data_if_disk_full(fs_stats: libc::statvfs) -> Result<()> {
    let free_percent = fs_stats.f_bfree * 100 / fs_stats.f_blocks;
    if free_percent < LOW_DISK_FREE_THRESHOLD {
        debug!("Freeing hiberdata: FS is only {}% free", free_percent);
        // TODO: Unlink hiberfile and metadata.
    } else {
        debug!("Not freeing hiberfile: FS is {}% free", free_percent);
    }

    Ok(())
}

fn resume_system(
    dry_run: bool,
    mut hiber_file: DiskFile,
    mut meta_file: DiskFile,
    mut metadata: HibernateMetadata,
) -> Result<()> {
    let mut snap_dev = open_snapshot(true)?;
    set_platform_mode(&mut snap_dev, false)?;
    read_image(&mut snap_dev, &mut hiber_file, &mut metadata)?;
    freeze_userspace(&mut snap_dev)?;
    drop(hiber_file);
    if dry_run {
        info!("Not launching resume image: in a dry run.");
        Ok(())
    } else {
        // Clear the valid flag and set the resume flag to indicate this image was resumed into.
        metadata.flags &= !HIBERNATE_META_FLAG_VALID;
        metadata.flags |= HIBERNATE_META_FLAG_RESUMED;
        metadata.write_to_disk(&mut meta_file)?;
        if let Err(e) = meta_file.sync_all() {
            return Err(HibernateError::FileSyncError(
                "Failed to sync metafile".to_string(),
                e,
            ));
        }

        // Jump into the restore image. This resumes execution in the lower
        // portion of suspend_system() on success.
        info!("Launching resume image");
        let result = atomic_restore(&mut snap_dev);
        error!("Resume failed");
        // If we are still executing then the resume failed. Mark it as such.
        metadata.flags |= HIBERNATE_META_FLAG_RESUME_FAILED;
        metadata.write_to_disk(&mut meta_file)?;
        result
    }
}

pub fn hibernate(dry_run: bool) -> Result<()> {
    info!("Beginning hibernate");
    if !Path::new(HIBERNATE_DIR).exists() {
        debug!("Creating hibernate directory");
        if let Err(e) = create_dir(HIBERNATE_DIR) {
            return Err(HibernateError::CreateDirectoryError(
                HIBERNATE_DIR.to_string(),
                e,
            ));
        }
    }

    let meta_file = preallocate_metadata_file()?;
    let hiber_file = preallocate_hiberfile()?;
    let fs_stats = get_fs_stats(Path::new(HIBERNATE_DIR))?;
    lock_process_memory()?;
    let mut swappiness = save_swappiness()?;
    write_swappiness(&mut swappiness.file, SUSPEND_SWAPPINESS)?;
    debug!("Syncing filesystems");
    unsafe {
        libc::sync();
    }

    let result = suspend_system(hiber_file, meta_file, dry_run);
    // After resume or a failed suspend attempt.
    unlock_process_memory();
    delete_data_if_disk_full(fs_stats)?;
    result
}

pub fn resume(dry_run: bool) -> Result<()> {
    info!("Beginning resume");
    let mut meta_file = open_metafile()?;
    debug!("Loading metadata");
    let metadata = HibernateMetadata::load_from_disk(&mut meta_file)?;
    if (metadata.flags & HIBERNATE_META_FLAG_VALID) == 0 {
        return Err(HibernateError::MetadataError(
            "No valid hibernate image".to_string(),
        ));
    }
    debug!("Opening hiberfile");
    let hiber_file = open_hiberfile()?;
    lock_process_memory()?;
    let result = resume_system(dry_run, hiber_file, meta_file, metadata);
    unlock_process_memory();
    result
}
