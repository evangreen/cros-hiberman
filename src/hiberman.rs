// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement hibernate functionality

pub mod cookie;
mod diskfile;
mod fiemap;
pub mod hiberlog;
mod hibermeta;
mod hiberutil;
mod imagemover;

use cookie::set_hibernate_cookie;
use diskfile::{BouncedDiskFile, DiskFile};
use hiberlog::{flush_log, redirect_log, replay_log_file, reset_log, HiberlogOut};
use hibermeta::{
    HibernateMetadata, HIBERNATE_META_FLAG_RESUMED, HIBERNATE_META_FLAG_RESUME_FAILED,
    HIBERNATE_META_FLAG_VALID,
};
use hiberutil::{path_to_stateful_block, HibernateError, Result};
pub use hiberutil::{HibernateOptions, ResumeOptions};
use imagemover::ImageMover;
use libc::{self, c_int, c_ulong, c_void, loff_t};
use std::ffi::CString;
use std::fs::{create_dir, metadata, File, OpenOptions};
use std::io::{BufRead, BufReader, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

static HIBERNATE_DIR: &str = "/mnt/stateful_partition/unencrypted/hibernate";
static HIBER_META_NAME: &str = "metadata";
static HIBER_META_SIZE: i64 = 1024 * 1024 * 8;
static HIBER_DATA_NAME: &str = "hiberfile";
static RESUME_LOG_FILE_NAME: &str = "resume_log";
static SUSPEND_LOG_FILE_NAME: &str = "suspend_log";
static SNAPSHOT_PATH: &str = "/dev/snapshot";
static SWAPPINESS_PATH: &str = "/proc/sys/vm/swappiness";
static SUSPEND_SWAPPINESS: i32 = 100;
// How many pages comprise a single buffer.
static BUFFER_PAGES: usize = 32;
// How low stateful free space is before we clean up the hiberfile after each
// hibernate.
static LOW_DISK_FREE_THRESHOLD: u64 = 10;
// The size of the preallocated log files.
static HIBER_LOG_SIZE: i64 = 1024 * 1024 * 4;

// Define snapshot device ioctl numbers.
static SNAPSHOT_FREEZE: c_ulong = 0x3301;
static SNAPSHOT_UNFREEZE: c_ulong = 0x3302;
static SNAPSHOT_ATOMIC_RESTORE: c_ulong = 0x3304;
static SNAPSHOT_GET_IMAGE_SIZE: c_ulong = 0x8008330e;
static SNAPSHOT_PLATFORM_SUPPORT: c_ulong = 0x330f;
static SNAPSHOT_POWER_OFF: c_ulong = 0x3310;
static SNAPSHOT_CREATE_IMAGE: c_ulong = 0x40043311;

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

// Freeze or unfreeze userspace.
fn freeze_userspace(snap_dev: &mut File, freeze: bool) -> Result<()> {
    let (name, value) = match freeze {
        true => ("FREEZE", SNAPSHOT_FREEZE),
        false => ("UNFREEZE", SNAPSHOT_UNFREEZE),
    };
    let rc = unsafe { libc::ioctl(snap_dev.as_raw_fd(), value, 0) };

    if rc < 0 {
        return Err(HibernateError::SnapshotIoctlError(
            name.to_string(),
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

fn snapshot_and_save(
    mut hiber_file: DiskFile,
    mut meta_file: BouncedDiskFile,
    snap_dev: &mut File,
    mut metadata: HibernateMetadata,
    options: &HibernateOptions,
) -> Result<()> {
    let block_path = path_to_stateful_block()?;
    set_platform_mode(snap_dev, false)?;
    // This is where the suspend path and resume path fork. On success,
    // both halves of these conditions execute, just at different times.
    if atomic_snapshot(snap_dev)? {
        // Suspend path. Everything after this point is invisible to the
        // hibernated kernel.
        write_image(snap_dev, &mut hiber_file, &mut metadata)?;
        drop(hiber_file);
        metadata.write_to_disk(&mut meta_file)?;
        drop(meta_file);
        // Set the hibernate cookie so the next boot knows to start in RO mode.
        info!("Setting hibernate cookie at {}", block_path);
        set_hibernate_cookie(Some(&block_path), true)?;
        if options.dry_run {
            info!("Not powering off due to dry run");
        } else {
            info!("Powering off");
        }

        // Flush out the hibernate log, and instead keep logs in memory.
        // Any logs beyond here are lost upon powerdown.
        flush_log();
        redirect_log(HiberlogOut::BufferInMemory, None);

        // Power the thing down.
        if !options.dry_run {
            snapshot_power_off(snap_dev)?;
            error!("Returned from power off");
        }

        // Unset the hibernate cookie.
        info!("Unsetting hibernate cookie at {}", block_path);
        set_hibernate_cookie(Some(&block_path), false)?;
    } else {
        // This is the resume path. First, forcefully reset the logger, which is some
        // stale partial state that the suspend path ultimately flushed and closed.
        // Keep logs in memory for now.
        reset_log();
        redirect_log(HiberlogOut::BufferInMemory, None);
        info!("Resumed from hibernate");
    }

    Ok(())
}

fn suspend_system(
    hiber_file: DiskFile,
    meta_file: BouncedDiskFile,
    options: &HibernateOptions,
) -> Result<()> {
    let metadata = HibernateMetadata::new();
    let mut snap_dev = open_snapshot(false)?;
    info!("Freezing userspace");
    freeze_userspace(&mut snap_dev, true)?;
    let mut result = snapshot_and_save(hiber_file, meta_file, &mut snap_dev, metadata, options);
    let freeze_result = freeze_userspace(&mut snap_dev, false);
    // Fail an otherwise happy suspend for failing to unfreeze, but don't
    // clobber an earlier error, as this is likely a downstream symptom.
    if freeze_result.is_err() && result.is_ok() {
        result = freeze_result;
    }
    result
}

fn replay_logs(push_resume_logs: bool) {
    // Push the hibernate logs that were taking after the snapshot (and
    // therefore after syslog became frozen) back into the syslog now.
    // These should be there on both success and failure cases.
    match open_log_file(true) {
        Ok(mut f) => replay_log_file(&mut f, "suspend log"),
        Err(e) => warn!("Failed to open suspend log: {}", e),
    }

    // If successfully resumed from hibernate, or in the bootstrapping kernel
    // after a failed resume attempt, also gather the resume logs
    // saved by the bootstrapping kernel.
    if push_resume_logs {
        match open_log_file(false) {
            Ok(mut f) => replay_log_file(&mut f, "resume log"),
            Err(e) => warn!("Failed to open resume log: {}", e),
        }
    }
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

fn launch_resume_image(
    mut meta_file: BouncedDiskFile,
    mut metadata: HibernateMetadata,
    snap_dev: &mut File,
) -> Result<()> {
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
    // portion of suspend_system() on success. Flush and stop the logging
    // before control is lost.
    info!("Launching resume image");

    // Flush out any pending resume logs, closing out the resume log file.
    flush_log();
    // Keep logs in memory for now.
    redirect_log(HiberlogOut::BufferInMemory, None);
    let result = atomic_restore(snap_dev);
    error!("Resume failed");
    // If we are still executing then the resume failed. Mark it as such.
    metadata.flags |= HIBERNATE_META_FLAG_RESUME_FAILED;
    metadata.write_to_disk(&mut meta_file)?;
    result
}

fn resume_system(
    options: &ResumeOptions,
    mut hiber_file: DiskFile,
    meta_file: BouncedDiskFile,
    mut metadata: HibernateMetadata,
) -> Result<()> {
    // Divert away from syslog early to maximize logs that get pushed
    // into the resumed kernel.
    let mut log_file = open_log_file(false)?;
    // Don't allow the logfile to log as it creates a deadlock.
    log_file.set_logging(false);
    // Start logging to the resume logger.
    redirect_log(HiberlogOut::File, Some(Box::new(log_file)));
    let mut snap_dev = open_snapshot(true)?;
    set_platform_mode(&mut snap_dev, false)?;
    read_image(&mut snap_dev, &mut hiber_file, &mut metadata)?;
    info!("Freezing userspace");
    freeze_userspace(&mut snap_dev, true)?;
    drop(hiber_file);
    let result;
    if options.dry_run {
        info!("Not launching resume image: in a dry run.");
        // Flush the resume file logs.
        flush_log();
        // Keep logs in memory, like launch_resume_image() does.
        redirect_log(HiberlogOut::BufferInMemory, None);
        result = Ok(())
    } else {
        result = launch_resume_image(meta_file, metadata, &mut snap_dev);
    }

    info!("Unfreezing userspace");
    if let Err(e) = freeze_userspace(&mut snap_dev, false) {
        error!("Failed to unfreeze userspace: {}", e);
    }

    result
}

pub fn hibernate(options: &HibernateOptions) -> Result<()> {
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
    // The resume log file needs to be preallocated now before the
    // snapshot is taken, though it's not used here.
    preallocate_log_file(false)?;
    let mut log_file = preallocate_log_file(true)?;
    // Don't allow the logfile to log as it creates a deadlock.
    log_file.set_logging(false);
    let fs_stats = get_fs_stats(Path::new(HIBERNATE_DIR))?;
    lock_process_memory()?;
    let mut swappiness = save_swappiness()?;
    write_swappiness(&mut swappiness.file, SUSPEND_SWAPPINESS)?;
    // Stop logging to syslog, and divert instead to a file since the
    // logging daemon's about to be frozen.
    redirect_log(HiberlogOut::File, Some(Box::new(log_file)));
    debug!("Syncing filesystems");
    unsafe {
        libc::sync();
    }

    let result = suspend_system(hiber_file, meta_file, options);
    unlock_process_memory();
    // Replay logs first because they happened earlier.
    replay_logs(result.is_ok() && !options.dry_run);
    // Now send any remaining logs and future logs to syslog.
    redirect_log(HiberlogOut::Syslog, None);
    delete_data_if_disk_full(fs_stats)?;
    result
}

pub fn resume_inner(options: &ResumeOptions) -> Result<()> {
    // Clear the cookie near the start to avoid situations where we repeatedly
    // try to resume but fail.
    let block_path = path_to_stateful_block()?;
    info!("Clearing hibernate cookie at '{}'", block_path);
    set_hibernate_cookie(Some(&block_path), false)?;
    info!("Cleared cookie");
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
    let result = resume_system(options, hiber_file, meta_file, metadata);
    unlock_process_memory();
    result
}

pub fn resume(options: &ResumeOptions) -> Result<()> {
    info!("Beginning resume");
    // Start keeping logs in memory, anticipating success.
    redirect_log(HiberlogOut::BufferInMemory, None);
    let result = resume_inner(options);
    // Replay earlier logs first.
    replay_logs(true);
    // Then move pending and future logs to syslog.
    redirect_log(HiberlogOut::Syslog, None);
    result
}

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
            let mut slice = [IoSliceMut::new(&mut buf)];
            let bytes_read = match file.read_vectored(&mut slice) {
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
