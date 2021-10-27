// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement hibernate suspend functionality

use crate::cookie::set_hibernate_cookie;
use crate::crypto::CryptoWriter;
use crate::diskfile::{BouncedDiskFile, DiskFile};
use crate::hiberlog::{flush_log, redirect_log, reset_log, HiberlogOut};
use crate::hibermeta::{
    HibernateMetadata, HIBERNATE_META_FLAG_ENCRYPTED, HIBERNATE_META_FLAG_VALID,
};
use crate::hiberutil::HibernateOptions;
use crate::hiberutil::{get_page_size, path_to_stateful_block, HibernateError, Result};
use crate::imagemover::ImageMover;
use crate::keyman::HibernateKeyManager;
use crate::snapdev::SnapshotDevice;
use crate::splitter::ImageSplitter;
use crate::{
    debug, error, get_fs_stats, info, lock_process_memory, preallocate_header_file,
    preallocate_hiberfile, preallocate_log_file, preallocate_metadata_file, replay_logs,
    save_swappiness, unlock_process_memory, warn, write_swappiness,
};
use libc;
use std::fs::create_dir;
use std::io::Write;
use std::path::Path;

const HIBERNATE_DIR: &str = "/mnt/stateful_partition/unencrypted/hibernate";
const SUSPEND_SWAPPINESS: i32 = 100;
// How many pages comprise a single buffer.
const BUFFER_PAGES: usize = 32;
// How low stateful free space is before we clean up the hiberfile after each
// hibernate.
const LOW_DISK_FREE_THRESHOLD: u64 = 10;

pub struct SuspendConductor {
    header_file: Option<DiskFile>,
    hiber_file: Option<DiskFile>,
    meta_file: Option<BouncedDiskFile>,
    snap_dev: Option<SnapshotDevice>,
    options: HibernateOptions,
    metadata: HibernateMetadata,
}

impl SuspendConductor {
    pub fn new() -> Result<Self> {
        Ok(SuspendConductor {
            header_file: None,
            hiber_file: None,
            meta_file: None,
            snap_dev: None,
            options: HibernateOptions::new(),
            metadata: HibernateMetadata::new()?,
        })
    }

    // Public entry point that hibernates the system, and returns either upon
    // failure to hibernate or after the system has resumed from a successful
    // hibernation.
    pub fn hibernate(&mut self, options: HibernateOptions) -> Result<()> {
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

        self.header_file = Some(preallocate_header_file()?);
        self.hiber_file = Some(preallocate_hiberfile()?);
        self.meta_file = Some(preallocate_metadata_file()?);
        self.options = options;

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
        if self.options.test_keys {
            key_manager.use_test_keys()?;
        } else {
            key_manager.load_public_key()?;
        }

        // Now that the public key is loaded, derive a metadata encryption key.
        key_manager.install_new_metadata_key(&mut self.metadata)?;

        // Stop logging to syslog, and divert instead to a file since the
        // logging daemon's about to be frozen.
        redirect_log(HiberlogOut::File, Some(Box::new(log_file)));
        debug!("Syncing filesystems");
        unsafe {
            libc::sync();
        }

        let result = self.suspend_system();
        unlock_process_memory();
        // Now send any remaining logs and future logs to syslog.
        redirect_log(HiberlogOut::Syslog, None);
        // Replay logs first because they happened earlier.
        replay_logs(
            result.is_ok() && !self.options.dry_run,
            !self.options.dry_run,
        );
        self.delete_data_if_disk_full(fs_stats)?;
        result
    }

    // Inner helper function to actually take the snapshot, save it to disk, and
    // shut down. Returns upon a failure to hibernate, or after a successful
    // hibernation has resumed.
    fn suspend_system(&mut self) -> Result<()> {
        self.snap_dev = Some(SnapshotDevice::new(false)?);
        info!("Freezing userspace");
        let snap_dev = self.snap_dev.as_mut().unwrap();
        snap_dev.freeze_userspace()?;
        let mut result = self.snapshot_and_save();
        // Take the snapshot device, and then drop it so that other processes
        // really unfreeze.
        let mut snap_dev = self.snap_dev.take().unwrap();
        let freeze_result = snap_dev.unfreeze_userspace();
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

    // Snapshot the system, write the result to disk, and power down. Returns
    // upon failure to hibernate, or after a hibernated system has successfully
    // resumed.
    fn snapshot_and_save(&mut self) -> Result<()> {
        let block_path = path_to_stateful_block()?;
        let dry_run = self.options.dry_run;
        let snap_dev = self.snap_dev.as_mut().unwrap();
        snap_dev.set_platform_mode(false)?;
        // This is where the suspend path and resume path fork. On success,
        // both halves of these conditions execute, just at different times.
        if snap_dev.atomic_snapshot()? {
            // Suspend path. Everything after this point is invisible to the
            // hibernated kernel.
            self.write_image()?;
            // Drop the hiber_file.
            self.hiber_file.take();
            let mut meta_file = self.meta_file.take().unwrap();
            meta_file.rewind()?;
            self.metadata.write_to_disk(&mut meta_file)?;
            drop(meta_file);
            // Set the hibernate cookie so the next boot knows to start in RO mode.
            info!("Setting hibernate cookie at {}", block_path);
            set_hibernate_cookie(Some(&block_path), true)?;
            if dry_run {
                info!("Not powering off due to dry run");
            } else {
                info!("Powering off");
            }

            // Flush out the hibernate log, and instead keep logs in memory.
            // Any logs beyond here are lost upon powerdown.
            flush_log();
            redirect_log(HiberlogOut::BufferInMemory, None);

            // Power the thing down.
            if !dry_run {
                let snap_dev = self.snap_dev.as_mut().unwrap();
                snap_dev.power_off()?;
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

    // Save the snapshot image to disk.
    fn write_image(&mut self) -> Result<()> {
        let snap_dev = self.snap_dev.as_mut().unwrap();
        let image_size = snap_dev.get_image_size()?;
        let page_size = get_page_size();
        let mut mover_dest: &mut dyn Write = self.hiber_file.as_mut().unwrap();
        let mut encryptor;
        if !self.options.unencrypted {
            encryptor = CryptoWriter::new(
                mover_dest,
                self.metadata.data_key,
                self.metadata.data_iv,
                true,
                page_size * BUFFER_PAGES,
            )?;
            mover_dest = &mut encryptor;
            self.metadata.flags |= HIBERNATE_META_FLAG_ENCRYPTED;
            debug!("Added encryption");
        } else {
            warn!("Warning: The hibernate image is unencrypted");
        }

        debug!("Hibernate image is {} bytes", image_size);
        let mut header_file = self.header_file.take().unwrap();
        let mut splitter = ImageSplitter::new(&mut header_file, mover_dest, &mut self.metadata);
        let mut writer = ImageMover::new(
            &mut snap_dev.file,
            &mut splitter,
            image_size,
            page_size,
            page_size * BUFFER_PAGES,
        )?;
        writer.move_all()?;
        info!("Wrote {} MB", image_size / 1024 / 1024);
        self.metadata.image_size = image_size as u64;
        self.metadata.flags |= HIBERNATE_META_FLAG_VALID;
        Ok(())
    }

    // Cleans up the hibernate files, releasing that space back to other usermode apps.
    fn delete_data_if_disk_full(&mut self, fs_stats: libc::statvfs) -> Result<()> {
        let free_percent = fs_stats.f_bfree * 100 / fs_stats.f_blocks;
        if free_percent < LOW_DISK_FREE_THRESHOLD {
            debug!("Freeing hiberdata: FS is only {}% free", free_percent);
            // TODO: Unlink hiberfile and metadata.
        } else {
            debug!("Not freeing hiberfile: FS is {}% free", free_percent);
        }

        Ok(())
    }
}
