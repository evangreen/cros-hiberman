// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement hibernate functionality

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
mod splitter;

use crate::dbus::HiberDbusConnection;
use cookie::set_hibernate_cookie;
use crypto::{CryptoReader, CryptoWriter};
use diskfile::{BouncedDiskFile, DiskFile};
use hiberlog::{clear_log_file, flush_log, redirect_log, replay_log_file, reset_log, HiberlogOut};
use hibermeta::{
    HibernateMetadata, HIBERNATE_HASH_SIZE, HIBERNATE_META_FLAG_ENCRYPTED,
    HIBERNATE_META_FLAG_RESUME_FAILED, HIBERNATE_META_FLAG_RESUME_LAUNCHED,
    HIBERNATE_META_FLAG_RESUME_STARTED, HIBERNATE_META_FLAG_VALID,
};
use hiberutil::{
    get_page_size, get_total_memory_pages, path_to_stateful_block, HibernateError, Result,
};
pub use hiberutil::{HibernateOptions, ResumeOptions};
use imagemover::ImageMover;
use keyman::HibernateKeyManager;
use libc::{self, c_int, c_ulong, c_void, loff_t};
use preloader::ImagePreloader;
use splitter::{ImageJoiner, ImageSplitter, HIBER_HEADER_MAX_SIZE};
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
static HIBER_HEADER_NAME: &str = "header";
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

struct HibernateContext {
    header_file: Option<DiskFile>,
    hiber_file: Option<DiskFile>,
    meta_file: Option<BouncedDiskFile>,
    snap_dev: Option<File>,
    metadata: HibernateMetadata,
}

struct ResumeContext<'a> {
    header_file: Option<DiskFile>,
    hiber_file: Option<DiskFile>,
    meta_file: Option<BouncedDiskFile>,
    snap_dev: Option<File>,
    metadata: HibernateMetadata,
    dbus_connection: &'a mut HiberDbusConnection,
    key_manager: HibernateKeyManager,
}

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

fn write_image(context: &mut HibernateContext, options: &HibernateOptions) -> Result<()> {
    let snap_dev = context.snap_dev.as_mut().unwrap();
    let image_size = get_image_size(snap_dev)?;
    let page_size = get_page_size();
    let mut mover_dest: &mut dyn Write = context.hiber_file.as_mut().unwrap();
    let mut encryptor;
    if !options.unencrypted {
        encryptor = CryptoWriter::new(
            mover_dest,
            context.metadata.data_key,
            context.metadata.data_iv,
            true,
            page_size * BUFFER_PAGES,
        )?;
        mover_dest = &mut encryptor;
        context.metadata.flags |= HIBERNATE_META_FLAG_ENCRYPTED;
        debug!("Added encryption");
    } else {
        warn!("Warning: The hibernate image is unencrypted");
    }

    debug!("Hibernate image is {} bytes", image_size);
    let mut header_file = context.header_file.take().unwrap();
    let mut splitter = ImageSplitter::new(&mut header_file, mover_dest, &mut context.metadata);
    let mut writer = ImageMover::new(
        snap_dev,
        &mut splitter,
        image_size,
        page_size,
        page_size * BUFFER_PAGES,
    )?;
    writer.move_all()?;
    info!("Wrote {} MB", image_size / 1024 / 1024);
    context.metadata.image_size = image_size as u64;
    context.metadata.flags |= HIBERNATE_META_FLAG_VALID;
    Ok(())
}

fn populate_seed(
    dbus_connection: &mut HiberDbusConnection,
    key_manager: &mut HibernateKeyManager,
) -> Result<()> {
    let got_seed_already = dbus_connection.has_seed_material();
    if !got_seed_already {
        debug!("Waiting for seed material");
        // Also print it to the console for the poor souls testing manually.
        // If you're stuck here, use --test-keys to skip this part, or
        // manually send something like this:
        // dbus-send --system --type=method_call --print-reply
        //    --dest=org.chromium.Hibernate /org/chromium/HibernateSeed
        //    org.chromium.HibernateSeedInterface.SetSeedMaterial
        //    "array:byte:0x31,0x32,0x33,0x34,.... (32 bytes)"
        println!("Waiting for seed material");
    }

    let seed = dbus_connection.get_seed_material()?;
    if !got_seed_already {
        debug!("Got seed material");
        // Use an exclamation point to congratulate that poor soul who's
        // been stuck here all afternoon.
        println!("Got seed material!")
    }

    key_manager.set_private_key(&seed)
}

// To get the kernel to do its big allocation, we sent one byte of data to it
// after sending the header pages. But now we're out of alignment for the main
// move. This function sends the rest of the page to get things realigned, and
// verifies the contents of the first byte.
fn read_first_partial_page(
    metadata: &HibernateMetadata,
    source: &mut dyn Read,
    dest: &mut dyn Write,
    page_size: usize,
) -> Result<()> {
    let mut buf = vec![0u8; page_size];
    // Get the whole page from the source, including the first byte.
    let bytes_read = match source.read(&mut buf[..]) {
        Ok(s) => s,
        Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
    };

    if bytes_read != page_size {
        return Err(HibernateError::IoSizeError(format!(
            "Read only {} of {} byte",
            bytes_read, page_size
        )));
    }

    if buf[0] != metadata.first_data_byte {
        // Print an error, but don't print the right answer.
        error!("First data byte of {:x} was incorrect", buf[0]);
        return Err(HibernateError::FirstDataByteMismatch());
    }

    // Now write most of the page.
    let bytes_written = match dest.write(&buf[1..]) {
        Ok(s) => s,
        Err(e) => {
            return Err(HibernateError::FileIoError(
                "Failed to write".to_string(),
                e,
            ))
        }
    };

    if bytes_written != page_size - 1 {
        return Err(HibernateError::IoSizeError(format!(
            "Wrote only {} of {} byte",
            bytes_written,
            page_size - 1
        )));
    }

    Ok(())
}

fn read_image(context: &mut ResumeContext, options: &ResumeOptions) -> Result<()> {
    let page_size = get_page_size();
    let snap_dev = context.snap_dev.as_mut().unwrap();
    let mut image_size = context.metadata.image_size;
    debug!("Resume image is {} bytes", image_size);
    let hiber_file = context.hiber_file.as_mut().unwrap();
    let mut header_file = context.header_file.take().unwrap();
    let mut joiner = ImageJoiner::new(&mut header_file, hiber_file);
    let mut mover_source: &mut dyn Read;

    // Fire up the preloader to start loading pages off of disk right away.
    let mut preloader;
    if options.no_preloader {
        info!("Not using preloader");
        mover_source = &mut joiner;
    } else {
        preloader = ImagePreloader::new(&mut joiner, image_size);
        // Pump the header pages directly into the kernel so the kernel gets
        // first rights to allocate the space it needs. We'll preload using
        // whatever memory is left.
        let header_pages = context.metadata.pagemap_pages;
        let header_size = header_pages as usize * page_size;
        debug!(
            "Loading {} header pages ({} bytes)",
            header_pages, header_size
        );
        let mut mover = ImageMover::new(
            &mut preloader,
            snap_dev,
            header_size as i64,
            page_size * BUFFER_PAGES,
            page_size,
        )?;
        mover.move_all()?;
        drop(mover);
        debug!("Done loading header");
        image_size -= header_size as u64;
        // Also write the first data byte, which is what triggers the kernel to
        // do its big allocation.
        match snap_dev.write(std::slice::from_ref(&context.metadata.first_data_byte)) {
            Ok(s) => {
                if s != 1 {
                    return Err(HibernateError::IoSizeError(format!(
                        "Wrote only {} of 1 byte",
                        s
                    )));
                }
            }
            Err(e) => {
                return Err(HibernateError::FileIoError(
                    "Failed to write one byte to snap dev".to_string(),
                    e,
                ))
            }
        }

        // Now that the kernel got its chunk, fill up the rest of memory with
        // data from disk.
        debug!("Preloading hibernate image");
        preloader.load_into_available_memory()?;
        mover_source = &mut preloader;
    }

    // Now that as much data as possible has been preloaded from disk, the next
    // step is to start decrypting it and push it to the kernel. Block waiting
    // on the authentication key material from cryptohome.
    let key_manager = &mut context.key_manager;
    let metadata = &mut context.metadata;
    if options.test_keys {
        key_manager.use_test_keys()?;
    } else {
        populate_seed(&mut context.dbus_connection, key_manager)?;
    }

    info!("Loading private metadata");
    key_manager.install_saved_metadata_key(metadata)?;
    metadata.load_private_data()?;
    let mut decryptor;
    if (metadata.flags & HIBERNATE_META_FLAG_ENCRYPTED) != 0 {
        decryptor = CryptoReader::new(
            mover_source,
            metadata.data_key,
            metadata.data_iv,
            false,
            page_size * BUFFER_PAGES,
        )?;

        mover_source = &mut decryptor;
        debug!("Image is encrypted");
    } else {
        if options.unencrypted {
            warn!("Image is not encrypted");
        } else {
            error!("Unencrypted images are not permitted without --unencrypted");
            return Err(HibernateError::ImageUnencryptedError());
        }
    }

    // If the preloader was used, then the first data byte was already sent down. Send down a partial page
    // Move from the image, which can read big chunks, to the snapshot dev, which only writes pages.
    if !options.no_preloader {
        debug!("Sending in partial page");
        read_first_partial_page(&metadata, mover_source, snap_dev, page_size)?;
        image_size -= page_size as u64;
    }

    let mut reader = ImageMover::new(
        mover_source,
        snap_dev,
        image_size as i64,
        page_size * BUFFER_PAGES,
        page_size,
    )?;
    reader.move_all()?;
    info!("Moved {} MB", image_size / 1024 / 1024);
    // Check the header pages hash. Ideally this would be done just after the
    // private data was loaded, but by then we've handed a mutable borrow out to
    // the mover source. This is fine too, as the kernel will reject writes if
    // the page list size is different. The worst an attacker can do is move
    // pages around to other RAM locations (the kernel ensures the pages are
    // RAM). The check here ensures we'll never jump into anything but the
    // original header.
    debug!("Validating header content");
    let mut header_hash = [0u8; HIBERNATE_HASH_SIZE];
    let header_pages = joiner.get_header_hash(&mut header_hash);
    if (header_pages == 0) || ((metadata.pagemap_pages as usize) != header_pages) {
        error!(
            "Metadata had {} pages, but {} were loaded",
            metadata.pagemap_pages, header_pages
        );
        return Err(HibernateError::HeaderContentLengthMismatch());
    }

    if metadata.header_hash != header_hash {
        error!("Metadata header hash mismatch");
        return Err(HibernateError::HeaderContentHashMismatch());
    }

    Ok(())
}

fn snapshot_and_save(context: &mut HibernateContext, options: &HibernateOptions) -> Result<()> {
    let block_path = path_to_stateful_block()?;
    let snap_dev = context.snap_dev.as_mut().unwrap();
    set_platform_mode(snap_dev, false)?;
    // This is where the suspend path and resume path fork. On success,
    // both halves of these conditions execute, just at different times.
    if atomic_snapshot(snap_dev)? {
        // Suspend path. Everything after this point is invisible to the
        // hibernated kernel.
        write_image(context, options)?;
        // Drop the hiber_file.
        context.hiber_file.take();
        let mut meta_file = context.meta_file.take().unwrap();
        meta_file.rewind()?;
        context.metadata.write_to_disk(&mut meta_file)?;
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
            let snap_dev = context.snap_dev.as_mut().unwrap();
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

fn suspend_system(context: &mut HibernateContext, options: &HibernateOptions) -> Result<()> {
    context.snap_dev = Some(open_snapshot(false)?);
    info!("Freezing userspace");
    let snap_dev = context.snap_dev.as_mut().unwrap();
    freeze_userspace(snap_dev, true)?;
    let mut result = snapshot_and_save(context, options);
    // Take the snapshot device, and then drop it so that other processes
    // really unfreeze.
    let mut snap_dev = context.snap_dev.take().unwrap();
    let freeze_result = freeze_userspace(&mut snap_dev, false);
    // Fail an otherwise happy suspend for failing to unfreeze, but don't
    // clobber an earlier error, as this is likely a downstream symptom.
    if freeze_result.is_err() {
        error!("Failed to unfreeze userspace: {:?}", freeze_result);
        if result.is_ok() {
            result = freeze_result;
        }
    } else {
        debug!("Unfroze userspace");
    }

    result
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

fn launch_resume_image(context: &mut ResumeContext) -> Result<()> {
    // Clear the valid flag and set the resume flag to indicate this image was resumed into.
    let metadata = &mut context.metadata;
    metadata.flags &= !HIBERNATE_META_FLAG_VALID;
    metadata.flags |= HIBERNATE_META_FLAG_RESUME_LAUNCHED;
    let mut meta_file = context.meta_file.take().unwrap();
    meta_file.rewind()?;
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
    let result = atomic_restore(context.snap_dev.as_mut().unwrap());
    error!("Resume failed");
    // If we are still executing then the resume failed. Mark it as such.
    metadata.flags |= HIBERNATE_META_FLAG_RESUME_FAILED;
    meta_file.rewind()?;
    metadata.write_to_disk(&mut meta_file)?;
    result
}

fn resume_system(context: &mut ResumeContext, options: &ResumeOptions) -> Result<()> {
    let mut log_file = open_log_file(false)?;
    // Don't allow the logfile to log as it creates a deadlock.
    log_file.set_logging(false);
    // Start logging to the resume logger.
    redirect_log(HiberlogOut::File, Some(Box::new(log_file)));
    let mut snap_dev = open_snapshot(true)?;
    set_platform_mode(&mut snap_dev, false)?;
    context.snap_dev = Some(snap_dev);
    read_image(context, options)?;
    info!("Freezing userspace");
    let snap_dev = context.snap_dev.as_mut().unwrap();
    freeze_userspace(snap_dev, true)?;
    // Drop the hiber file.
    context.hiber_file.take();
    let result;
    if options.dry_run {
        info!("Not launching resume image: in a dry run.");
        // Flush the resume file logs.
        flush_log();
        // Keep logs in memory, like launch_resume_image() does.
        redirect_log(HiberlogOut::BufferInMemory, None);
        result = Ok(())
    } else {
        result = launch_resume_image(context);
    }

    info!("Unfreezing userspace");
    // Take the snap_dev, unfreeze userspace, and drop it.
    let mut snap_dev = context.snap_dev.take().unwrap();
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

    let mut context = HibernateContext {
        header_file: Some(preallocate_header_file()?),
        hiber_file: Some(preallocate_hiberfile()?),
        meta_file: Some(preallocate_metadata_file()?),
        snap_dev: None,
        metadata: HibernateMetadata::new()?,
    };

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
    let mut key_manager = HibernateKeyManager::new();
    // Set up the hibernate metadata encryption keys. This was populated
    // at login time by a previous instance of this process.
    if options.test_keys {
        key_manager.use_test_keys()?;
    } else {
        key_manager.load_public_key()?;
    }

    // Now that the public key is loaded, derive a metadata encryption key.
    key_manager.install_new_metadata_key(&mut context.metadata)?;

    // Stop logging to syslog, and divert instead to a file since the
    // logging daemon's about to be frozen.
    redirect_log(HiberlogOut::File, Some(Box::new(log_file)));
    debug!("Syncing filesystems");
    unsafe {
        libc::sync();
    }

    let result = suspend_system(&mut context, options);
    unlock_process_memory();
    // Now send any remaining logs and future logs to syslog.
    redirect_log(HiberlogOut::Syslog, None);
    // Replay logs first because they happened earlier.
    replay_logs(result.is_ok() && !options.dry_run, !options.dry_run);
    delete_data_if_disk_full(fs_stats)?;
    result
}

fn resume_inner(options: &ResumeOptions, dbus_connection: &mut HiberDbusConnection) -> Result<()> {
    // Clear the cookie near the start to avoid situations where we repeatedly
    // try to resume but fail.
    let block_path = path_to_stateful_block()?;
    info!("Clearing hibernate cookie at '{}'", block_path);
    set_hibernate_cookie(Some(&block_path), false)?;
    info!("Cleared cookie");
    let mut meta_file = open_metafile()?;
    debug!("Loading metadata");
    let mut metadata = HibernateMetadata::load_from_disk(&mut meta_file)?;
    if (metadata.flags & HIBERNATE_META_FLAG_VALID) == 0 {
        return Err(HibernateError::MetadataError(
            "No valid hibernate image".to_string(),
        ));
    }

    // Mark that resume was attempted on this image in case it's the last thing
    // we do! This also clears out the private metadata on disk, getting the
    // (encrypted) data key off of disk. If this is just a dry run, don't make
    // any changes.
    metadata.dont_save_private_data();
    if !options.dry_run {
        metadata.flags &= !HIBERNATE_META_FLAG_VALID;
        metadata.flags |= HIBERNATE_META_FLAG_RESUME_STARTED;
        debug!("Clearing valid flag on metadata: {:x}", metadata.flags);
        meta_file.rewind()?;
        metadata.write_to_disk(&mut meta_file)?;
    }

    debug!("Opening hiberfile");
    let hiber_file = open_hiberfile()?;
    lock_process_memory()?;
    let mut resume_context = ResumeContext {
        header_file: Some(open_header_file()?),
        hiber_file: Some(hiber_file),
        meta_file: Some(meta_file),
        metadata,
        snap_dev: None,
        dbus_connection,
        key_manager: HibernateKeyManager::new(),
    };

    let result = resume_system(&mut resume_context, options);
    unlock_process_memory();
    result
}

fn save_public_key(dbus_connection: &mut HiberDbusConnection) -> Result<()> {
    info!("Saving public key for future hibernate");
    let mut key_manager = HibernateKeyManager::new();
    populate_seed(dbus_connection, &mut key_manager)?;
    key_manager.save_public_key()
}

pub fn resume(options: &ResumeOptions) -> Result<()> {
    info!("Beginning resume");
    // Fire up the dbus server.
    let mut dbus_connection = HiberDbusConnection::new()?;
    dbus_connection.spawn_dbus_server()?;
    // Start keeping logs in memory, anticipating success.
    redirect_log(HiberlogOut::BufferInMemory, None);
    let mut result = resume_inner(options, &mut dbus_connection);
    // Replay earlier logs first. Don't wipe the logs out if this is just a dry
    // run.
    replay_logs(true, !options.dry_run);
    // Then move pending and future logs to syslog.
    redirect_log(HiberlogOut::Syslog, None);
    // Unless the test keys are being used, wait for the key material from
    // cryptohome and save the public portion for a later hibernate.
    if !options.test_keys {
        let save_result = save_public_key(&mut dbus_connection);
        if matches!(result, Ok(())) {
            result = save_result;
        }
    }

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
