// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement hibernate resume functionality

use crate::cookie::set_hibernate_cookie;
use crate::crypto::CryptoReader;
use crate::dbus::HiberDbusConnection;
use crate::diskfile::{BouncedDiskFile, DiskFile};
use crate::hiberlog::{flush_log, redirect_log, HiberlogOut};
use crate::hibermeta::{
    HibernateMetadata, HIBERNATE_HASH_SIZE, HIBERNATE_META_FLAG_ENCRYPTED,
    HIBERNATE_META_FLAG_RESUME_FAILED, HIBERNATE_META_FLAG_RESUME_LAUNCHED,
    HIBERNATE_META_FLAG_RESUME_STARTED, HIBERNATE_META_FLAG_VALID,
};
use crate::hiberutil::ResumeOptions;
use crate::hiberutil::{get_page_size, path_to_stateful_block, HibernateError, Result};
use crate::imagemover::ImageMover;
use crate::keyman::HibernateKeyManager;
use crate::preloader::ImagePreloader;
use crate::snapdev::SnapshotDevice;
use crate::splitter::ImageJoiner;
use crate::{
    debug, error, info, lock_process_memory, open_header_file, open_hiberfile, open_log_file,
    open_metafile, replay_logs, unlock_process_memory, warn, BUFFER_PAGES,
};
use std::io::{Read, Write};

pub struct ResumeConductor {
    header_file: Option<DiskFile>,
    hiber_file: Option<DiskFile>,
    meta_file: Option<BouncedDiskFile>,
    snap_dev: Option<SnapshotDevice>,
    metadata: HibernateMetadata,
    dbus_connection: Option<HiberDbusConnection>,
    key_manager: HibernateKeyManager,
    options: ResumeOptions,
}

impl ResumeConductor {
    pub fn new() -> Result<Self> {
        Ok(ResumeConductor {
            header_file: None,
            hiber_file: None,
            meta_file: None,
            snap_dev: None,
            metadata: HibernateMetadata::new()?,
            dbus_connection: None,
            key_manager: HibernateKeyManager::new(),
            options: ResumeOptions::new(),
        })
    }

    // Public entry point into the resume process. In the case of a successful
    // resume, this does not return, as the resume image is running instead. In
    // the case of resume failure, an error is returned.
    pub fn resume(&mut self, options: ResumeOptions) -> Result<()> {
        info!("Beginning resume");
        self.options = options;
        // Fire up the dbus server.
        self.dbus_connection = Some(HiberDbusConnection::new()?);
        self.dbus_connection.as_mut().unwrap().spawn_dbus_server()?;
        // Start keeping logs in memory, anticipating success.
        redirect_log(HiberlogOut::BufferInMemory, None);
        let mut result = self.resume_inner();
        // Replay earlier logs first. Don't wipe the logs out if this is just a dry
        // run.
        replay_logs(true, !self.options.dry_run);
        // Then move pending and future logs to syslog.
        redirect_log(HiberlogOut::Syslog, None);
        // Unless the test keys are being used, wait for the key material from
        // cryptohome and save the public portion for a later hibernate.
        if !self.options.test_keys {
            let save_result = self.save_public_key();
            if matches!(result, Ok(())) {
                result = save_result;
            }
        }

        result
    }

    // Helper function to perform the meat of the resume action now that the
    // logging is routed.
    fn resume_inner(&mut self) -> Result<()> {
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
        if !self.options.dry_run {
            metadata.flags &= !HIBERNATE_META_FLAG_VALID;
            metadata.flags |= HIBERNATE_META_FLAG_RESUME_STARTED;
            debug!("Clearing valid flag on metadata: {:x}", metadata.flags);
            meta_file.rewind()?;
            metadata.write_to_disk(&mut meta_file)?;
        }

        debug!("Opening hiberfile");
        let hiber_file = open_hiberfile()?;
        lock_process_memory()?;
        self.header_file = Some(open_header_file()?);
        self.hiber_file = Some(hiber_file);
        self.meta_file = Some(meta_file);
        self.metadata = metadata;
        let result = self.resume_system();
        unlock_process_memory();
        result
    }

    // Inner helper function to read the resume image and launch it.
    fn resume_system(&mut self) -> Result<()> {
        let mut log_file = open_log_file(false)?;
        // Don't allow the logfile to log as it creates a deadlock.
        log_file.set_logging(false);
        // Start logging to the resume logger.
        redirect_log(HiberlogOut::File, Some(Box::new(log_file)));
        let mut snap_dev = SnapshotDevice::new(true)?;
        snap_dev.set_platform_mode(false)?;
        self.snap_dev = Some(snap_dev);
        self.read_image()?;
        info!("Freezing userspace");
        let snap_dev = self.snap_dev.as_mut().unwrap();
        snap_dev.freeze_userspace()?;
        let result;
        if self.options.dry_run {
            info!("Not launching resume image: in a dry run.");
            // Flush the resume file logs.
            flush_log();
            // Keep logs in memory, like launch_resume_image() does.
            redirect_log(HiberlogOut::BufferInMemory, None);
            result = Ok(())
        } else {
            result = self.launch_resume_image();
        }

        info!("Unfreezing userspace");
        // Take the snap_dev, unfreeze userspace, and drop it.
        let mut snap_dev = self.snap_dev.take().unwrap();
        if let Err(e) = snap_dev.unfreeze_userspace() {
            error!("Failed to unfreeze userspace: {}", e);
        }

        result
    }

    // Load the resume image from disk into memory.
    fn read_image(&mut self) -> Result<()> {
        let page_size = get_page_size();
        let snap_dev = self.snap_dev.as_mut().unwrap();
        let mut image_size = self.metadata.image_size;
        debug!("Resume image is {} bytes", image_size);
        // Create the image joiner, which combines the header file and the data
        // file into one contiguous read stream.
        let mut hiber_file = self.hiber_file.take().unwrap();
        let mut header_file = self.header_file.take().unwrap();
        let mut joiner = ImageJoiner::new(&mut header_file, &mut hiber_file);
        let mut mover_source: &mut dyn Read;

        // Fire up the preloader to start loading pages off of disk right away.
        // We preload data because disk latency tends to be the long pole in the
        // tent, but we don't yet have the decryption keys needed to decrypt the
        // data and feed it to the kernel. Preloading is an attempt to frontload
        // that disk latency while the user is still authenticating (eg typing
        // in their password).
        let mut preloader;
        if self.options.no_preloader {
            info!("Not using preloader");
            mover_source = &mut joiner;
        } else {
            preloader = ImagePreloader::new(&mut joiner, image_size);
            // Pump the header pages directly into the kernel. After the header
            // pages are fed to the kernel, the kernel will do a giant
            // allocation to make space for the resume image. We'll preload
            // using whatever memory is left. Note that if we don't feed in the
            // header pages early, and instead preload to fill memory before the
            // kernel attempts its giant resume image allocation, the kernel
            // tends to crash the system by asking for too much memory too
            // quickly.
            let header_pages = self.metadata.pagemap_pages;
            let header_size = header_pages as usize * page_size;
            debug!(
                "Loading {} header pages ({} bytes)",
                header_pages, header_size
            );
            let mut mover = ImageMover::new(
                &mut preloader,
                &mut snap_dev.file,
                header_size as i64,
                page_size * BUFFER_PAGES,
                page_size,
            )?;
            mover.move_all()?;
            drop(mover);
            debug!("Done loading header pages");
            image_size -= header_size as u64;

            // Also write the first data byte, which is what actually triggers
            // the kernel to do its big allocation.
            match snap_dev
                .file
                .write(std::slice::from_ref(&self.metadata.first_data_byte))
            {
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

            // By now the kernel has done its own allocation for hibernate image
            // space. We can use the remaining memory to preload from disk.
            debug!("Preloading hibernate image");
            preloader.load_into_available_memory()?;
            mover_source = &mut preloader;
        }

        // Now that as much data as possible has been preloaded from disk, the next
        // step is to start decrypting it and push it to the kernel. Block waiting
        // on the authentication key material from cryptohome.
        if self.options.test_keys {
            self.key_manager.use_test_keys()?;
        } else {
            // This is what blocks waiting for seed material.
            self.populate_seed()?;
        }

        // With the seed material in hand, decrypt the private data, and fire up
        // the big image decryptor.
        info!("Loading private metadata");
        let metadata = &mut self.metadata;
        self.key_manager.install_saved_metadata_key(metadata)?;
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
            if self.options.unencrypted {
                warn!("Image is not encrypted");
            } else {
                error!("Unencrypted images are not permitted without --unencrypted");
                return Err(HibernateError::ImageUnencryptedError());
            }
        }

        // If the preloader was used, then the first data byte was already sent
        // down. Send down a partial page Move from the image, which can read
        // big chunks, to the snapshot dev, which only writes pages.
        if !self.options.no_preloader {
            debug!("Sending in partial page");
            self.read_first_partial_page(mover_source, page_size)?;
            image_size -= page_size as u64;
        }

        // Fire up the big image pump into the kernel.
        let snap_dev = self.snap_dev.as_mut().unwrap();
        let mut reader = ImageMover::new(
            mover_source,
            &mut snap_dev.file,
            image_size as i64,
            page_size * BUFFER_PAGES,
            page_size,
        )?;
        reader.move_all()?;
        info!("Moved {} MB", image_size / 1024 / 1024);
        // Check the header pages hash. Ideally this would be done just after
        // the private data was loaded, but by then we've handed a mutable
        // borrow out to the mover source. This is fine too, as the kernel will
        // reject writes if the page list size is different. The worst an
        // attacker can do is move pages around to other RAM locations (the
        // kernel ensures the pages are RAM). The check here ensures we'll never
        // jump into anything but the original header.
        debug!("Validating header content");
        let mut header_hash = [0u8; HIBERNATE_HASH_SIZE];
        let header_pages = joiner.get_header_hash(&mut header_hash);
        let metadata = &mut self.metadata;
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

    // Wait for the hibernate key seed, and then feed it to the key manager.
    fn populate_seed(&mut self) -> Result<()> {
        let dbus_connection = self.dbus_connection.as_mut().unwrap();
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

        // Block waiting for seed material from cryptohome.
        let seed = dbus_connection.get_seed_material()?;
        if !got_seed_already {
            debug!("Got seed material");
            // Use an exclamation point to congratulate that poor soul who's
            // been stuck here all afternoon.
            println!("Got seed material!")
        }

        self.key_manager.set_private_key(&seed)
    }

    // To get the kernel to do its big allocation, we sent one byte of data to
    // it after sending the header pages. But now we're out of alignment for the
    // main move. This function sends the rest of the page to get things
    // realigned, and verifies the contents of the first byte. This keeps the
    // ImageMover uncomplicated and none the wiser.
    fn read_first_partial_page(&mut self, source: &mut dyn Read, page_size: usize) -> Result<()> {
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

        if buf[0] != self.metadata.first_data_byte {
            // Print an error, but don't print the right answer.
            error!("First data byte of {:x} was incorrect", buf[0]);
            return Err(HibernateError::FirstDataByteMismatch());
        }

        // Now write most of the page.
        let bytes_written = match self.snap_dev.as_mut().unwrap().file.write(&buf[1..]) {
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

    // Jump into the already-loaded resume image.
    fn launch_resume_image(&mut self) -> Result<()> {
        // Clear the valid flag and set the resume flag to indicate this image
        // was resumed into.
        let metadata = &mut self.metadata;
        metadata.flags &= !HIBERNATE_META_FLAG_VALID;
        metadata.flags |= HIBERNATE_META_FLAG_RESUME_LAUNCHED;
        let mut meta_file = self.meta_file.take().unwrap();
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
        let snap_dev = self.snap_dev.as_mut().unwrap();
        let result = snap_dev.atomic_restore();
        error!("Resume failed");
        // If we are still executing then the resume failed. Mark it as such.
        metadata.flags |= HIBERNATE_META_FLAG_RESUME_FAILED;
        meta_file.rewind()?;
        metadata.write_to_disk(&mut meta_file)?;
        result
    }

    // Save the public key for future hibernate attempts.
    fn save_public_key(&mut self) -> Result<()> {
        info!("Saving public key for future hibernate");
        let key_manager = HibernateKeyManager::new();
        self.populate_seed()?;
        key_manager.save_public_key()
    }
}
