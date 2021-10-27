// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement hibernate functionality

pub mod cat;
pub mod cookie;
mod crypto;
mod dbus;
mod diskfile;
mod fiemap;
pub mod hiberlog;
mod hibermeta;
mod hiberutil;
mod imagemover;
mod keyman;
mod mmapbuf;
mod preloader;
mod resume;
mod snapdev;
mod splitter;
mod suspend;

use diskfile::{BouncedDiskFile, DiskFile};
use hiberlog::{clear_log_file, replay_log_file};
use hiberutil::{get_page_size, get_total_memory_pages, HibernateError, Result};
pub use hiberutil::{HibernateOptions, ResumeOptions};
use libc;
use resume::ResumeConductor;
use splitter::HIBER_HEADER_MAX_SIZE;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use suspend::SuspendConductor;

static HIBERNATE_DIR: &str = "/mnt/stateful_partition/unencrypted/hibernate";
static HIBER_META_NAME: &str = "metadata";
static HIBER_META_SIZE: i64 = 1024 * 1024 * 8;
static HIBER_HEADER_NAME: &str = "header";
static HIBER_DATA_NAME: &str = "hiberfile";
static RESUME_LOG_FILE_NAME: &str = "resume_log";
static SUSPEND_LOG_FILE_NAME: &str = "suspend_log";
static SWAPPINESS_PATH: &str = "/proc/sys/vm/swappiness";
// How many pages comprise a single buffer.
static BUFFER_PAGES: usize = 32;
// The size of the preallocated log files.
static HIBER_LOG_SIZE: i64 = 1024 * 1024 * 4;

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

fn get_total_memory_mb() -> Result<u32> {
    let pagesize = get_page_size() as i64;
    let pagecount = get_total_memory_pages() as i64;

    debug!("Pagesize {} pagecount {}", pagesize, pagecount);
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

fn preallocate_metadata_file() -> Result<BouncedDiskFile> {
    let metadata_path = Path::new(HIBERNATE_DIR).join(HIBER_META_NAME);
    let mut meta_file = preallocate_file(&metadata_path, HIBER_META_SIZE)?;
    BouncedDiskFile::new(&mut meta_file, None)
}

// Preallocate the suspend or resume log file.
fn preallocate_log_file(suspend: bool) -> Result<BouncedDiskFile> {
    let name = match suspend {
        true => SUSPEND_LOG_FILE_NAME,
        false => RESUME_LOG_FILE_NAME,
    };

    let log_file_path = Path::new(HIBERNATE_DIR).join(name);
    let mut log_file = preallocate_file(&log_file_path, HIBER_LOG_SIZE)?;
    BouncedDiskFile::new(&mut log_file, None)
}

fn preallocate_header_file() -> Result<DiskFile> {
    let path = Path::new(HIBERNATE_DIR).join(HIBER_HEADER_NAME);
    let mut file = preallocate_file(&path, HIBER_HEADER_MAX_SIZE)?;
    DiskFile::new(&mut file, None)
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

// Open a pre-existing disk file with bounce buffer,
// still with read and write permissions.
fn open_bounced_disk_file(path: &Path) -> Result<BouncedDiskFile> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) => return Err(HibernateError::OpenFileError(path.display().to_string(), e)),
    };

    BouncedDiskFile::new(&mut file, None)
}

// Open a pre-existing header file, still with read and write permissions.
fn open_header_file() -> Result<DiskFile> {
    let path = Path::new(HIBERNATE_DIR).join(HIBER_HEADER_NAME);
    open_disk_file(&path)
}

// Open a pre-existing hiberfile, still with read and write permissions.
fn open_hiberfile() -> Result<DiskFile> {
    let hiberfile_path = Path::new(HIBERNATE_DIR).join(HIBER_DATA_NAME);
    open_disk_file(&hiberfile_path)
}

// Open a pre-existing hiberfile, still with read and write permissions.
fn open_metafile() -> Result<BouncedDiskFile> {
    let hiberfile_path = Path::new(HIBERNATE_DIR).join(HIBER_META_NAME);
    open_bounced_disk_file(&hiberfile_path)
}

// Open one of the log files, either the suspend or resume log.
fn open_log_file(suspend: bool) -> Result<BouncedDiskFile> {
    let name = match suspend {
        true => SUSPEND_LOG_FILE_NAME,
        false => RESUME_LOG_FILE_NAME,
    };

    let path = Path::new(HIBERNATE_DIR).join(name);
    open_bounced_disk_file(&path)
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

fn replay_log(suspend_log: bool, clear: bool) {
    let name = match suspend_log {
        true => "suspend log",
        false => "resume log",
    };

    let mut log_file = match open_log_file(suspend_log) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to open {}: {}", name, e);
            return;
        }
    };

    replay_log_file(&mut log_file, name);
    if clear {
        if let Err(e) = clear_log_file(&mut log_file) {
            warn!("Failed to clear {}: {}", name, e);
        }
    }
}

fn replay_logs(push_resume_logs: bool, clear: bool) {
    // Push the hibernate logs that were taken after the snapshot (and
    // therefore after syslog became frozen) back into the syslog now.
    // These should be there on both success and failure cases.
    replay_log(true, clear);

    // If successfully resumed from hibernate, or in the bootstrapping kernel
    // after a failed resume attempt, also gather the resume logs
    // saved by the bootstrapping kernel.
    if push_resume_logs {
        replay_log(false, clear);
    }
}

pub fn hibernate(options: HibernateOptions) -> Result<()> {
    let mut conductor = SuspendConductor::new()?;
    conductor.hibernate(options)
}

pub fn resume(options: ResumeOptions) -> Result<()> {
    let mut conductor = ResumeConductor::new()?;
    conductor.resume(options)
}
