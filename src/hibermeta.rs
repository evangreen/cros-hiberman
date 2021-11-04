// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement support for managing hibernate metadata.

use std::io::{IoSliceMut, Read, Write};
use openssl::symm::{Cipher, Crypter, Mode};
use sys_util::rand::{rand_bytes, Source};
use crate::diskfile::BouncedDiskFile;
use crate::hiberutil::{any_as_u8_slice, HibernateError, Result};

/// Magic value used to recognize a hibernate metadata struct.
const HIBERNATE_META_MAGIC: u64 = 0x6174654D72626948;

/// Version of the structure contents. Bump this up whenever the
/// structure changes.
const HIBERNATE_META_VERSION: u32 = 1;

// Define hibernate metadata flags.
/// This flag is set if the hibernate image is valid and ready to be resumed to.
pub const HIBERNATE_META_FLAG_VALID: u32 = 0x00000001;

/// This flag is set if the image has already been attempted for resume. When
/// this flag is set the VALID flag is cleared.
pub const HIBERNATE_META_FLAG_RESUME_STARTED: u32 = 0x00000002;

/// This flag is set if the image was fully loaded and a resume launch was
/// attempted.
pub const HIBERNATE_META_FLAG_RESUME_LAUNCHED: u32 = 0x00000004;

/// This flag is set if the image has already been resumed into, but the resume
/// attempt failed. The RESUMED flag will also be set.
pub const HIBERNATE_META_FLAG_RESUME_FAILED: u32 = 0x00000008;

/// This flag is set if the image is encrypted.
pub const HIBERNATE_META_FLAG_ENCRYPTED: u32 = 0x00000010;

/// Define the mask of all valid flags.
pub const HIBERNATE_META_VALID_FLAGS: u32 = HIBERNATE_META_FLAG_VALID
    | HIBERNATE_META_FLAG_RESUME_STARTED
    | HIBERNATE_META_FLAG_RESUME_LAUNCHED
    | HIBERNATE_META_FLAG_RESUME_FAILED
    | HIBERNATE_META_FLAG_ENCRYPTED;

/// Define the size of the hash field in the metadata.
pub const HIBERNATE_HASH_SIZE: usize = 32;

/// Define the size of the hibernate data symmetric encryption key.
pub const HIBERNATE_DATA_KEY_SIZE: usize = 16;
pub const HIBERNATE_DATA_IV_SIZE: usize = HIBERNATE_DATA_KEY_SIZE;

/// Define the size of the encrypted private area. Bump this up (and
/// bump the version) if PrivateHibernateMetadata outgrows it.
pub const HIBERNATE_META_PRIVATE_SIZE: usize = 0x400;

/// Define the size of the asymmetric key pairs used to encrypt the hibernate
/// metadata.
pub const HIBERNATE_META_KEY_SIZE: usize = 32;

/// Define the software representation of the hibernate metadata.
pub struct HibernateMetadata {
    /// The size of the hibernate image data.
    pub image_size: u64,
    /// Flags. See HIBERNATE_META_FLAG_* definitions.
    pub flags: u32,
    /// Number of pages in the image's header and pagemap.
    pub pagemap_pages: u32,
    /// Hash of the header pages.
    pub header_hash: [u8; HIBERNATE_HASH_SIZE],
    /// Hibernate symmetric encryption key.
    pub data_key: [u8; HIBERNATE_DATA_KEY_SIZE],
    /// Hibernate symmetric encryption IV (chosen randomly).
    pub data_iv: [u8; HIBERNATE_DATA_IV_SIZE],
    /// The first byte of data, in plaintext. This is needed to coerce the kernel
    /// into doing its image allocation. Random IV used for metadata encryption.
    pub first_data_byte: u8,
    /// Public side of the ephemeral key pair used in Diffie-Hellman to derive
    /// the metadata key.
    pub meta_eph_public: [u8; HIBERNATE_META_KEY_SIZE],
    /// Random IV used for metadata encryption.
    meta_iv: [u8; HIBERNATE_DATA_IV_SIZE],
    /// The not-yet-decrypted private data.
    private_blob: Option<[u8; HIBERNATE_META_PRIVATE_SIZE]>,
    /// The key used to decrypt private metadata.
    meta_key: Option<[u8; HIBERNATE_DATA_KEY_SIZE]>,
    /// Define whether or not to save private data to disk anymore or not. This
    /// can be cleared when the metadata is only being written out as a debugging
    /// breadcrumb.
    save_private_data: bool,
}

/// Define the structure of the public hibernate metadata, which is written
/// out to disk unencrypted.
/// Use repr(C) to ensure a consistent structure layout.
#[repr(C)]
pub struct PublicHibernateMetadata {
    /// This must be set to HIBERNATE_META_MAGIC.
    magic: u64,
    /// This must be set to HIBERNATE_META_VERSION.
    version: u32,
    /// Number of pages in the image's header and pagemap.
    pagemap_pages: u32,
    /// The size of the hibernate image data.
    image_size: u64,
    /// Flags. See HIBERNATE_META_FLAG_* definitions.
    flags: u32,
    /// The first byte of data, needed to coerce the kernel into doing its big
    /// allocation.
    first_data_byte: u8,
    /// Public side of the ephemeral key pair used in Diffie-Hellman to derive
    /// the metadata key.
    meta_eph_public: [u8; HIBERNATE_META_KEY_SIZE],
    /// IV used for private portion of metadata.
    private_iv: [u8; HIBERNATE_DATA_IV_SIZE],
    /// Encrypted portion.
    private: [u8; HIBERNATE_META_PRIVATE_SIZE],
}

/// Define the structure of the private hibernate metadata, which is written
/// out to disk encrypted.
/// Use repr(C) to ensure a consistent structure layout.
#[repr(C)]
pub struct PrivateHibernateMetadata {
    /// This must be set to HIBERNATE_META_VERSION.
    version: u32,
    /// Number of pages in the image's header and pagemap.
    pagemap_pages: u32,
    /// The size of the hibernate image data.
    image_size: u64,
    /// Flags. See HIBERNATE_META_FLAG_* definitions.
    flags: u32,
    /// Hibernate symmetric encryption key.
    data_key: [u8; HIBERNATE_DATA_KEY_SIZE],
    /// Hibernate symmetric encryption IV (chosen randomly).
    data_iv: [u8; HIBERNATE_DATA_IV_SIZE],
    /// Hash of the header pages.
    header_hash: [u8; HIBERNATE_HASH_SIZE],
}

impl HibernateMetadata {
    /// Create a new metadata structure. The data key, data IV, and metadata IV
    /// will be initialized with data from /dev/urandom.
    pub fn new() -> Result<Self> {
        let mut data_key = [0u8; HIBERNATE_DATA_KEY_SIZE];
        Self::fill_random(&mut data_key)?;
        let mut data_iv = [0u8; HIBERNATE_DATA_IV_SIZE];
        Self::fill_random(&mut data_iv)?;
        let mut meta_iv = [0u8; HIBERNATE_DATA_IV_SIZE];
        Self::fill_random(&mut meta_iv)?;
        // Initialize the other keys with random junk as well to avoid bugs
        // where zeroed keys get used. These should never actually get used with
        // the random data (they'd be undecryptable if they were).
        let mut meta_eph_public = [0u8; HIBERNATE_META_KEY_SIZE];
        Self::fill_random(&mut meta_eph_public)?;
        Ok(Self {
            image_size: 0,
            flags: 0,
            pagemap_pages: 0,
            header_hash: [0u8; HIBERNATE_HASH_SIZE],
            data_key,
            data_iv,
            first_data_byte: 0,
            meta_iv,
            meta_eph_public,
            private_blob: None,
            meta_key: None,
            save_private_data: true,
        })
    }

    /// Create a new metadata object based on the contents of the C structure
    /// data.
    fn load_from_data(pubdata: &PublicHibernateMetadata) -> Result<Self> {
        if pubdata.magic != HIBERNATE_META_MAGIC {
            return Err(HibernateError::MetadataError(format!(
                "Invalid metadata magic: {:x?}, expected {:x?}",
                pubdata.magic, HIBERNATE_META_MAGIC
            )));
        }

        if pubdata.version != HIBERNATE_META_VERSION {
            return Err(HibernateError::MetadataError(format!(
                "Invalid public metadata version: {:x?}, expected {:x?}",
                pubdata.version, HIBERNATE_META_VERSION
            )));
        }

        if (pubdata.flags & !HIBERNATE_META_VALID_FLAGS) != 0 {
            return Err(HibernateError::MetadataError(format!(
                "Invalid flags: {:x?}, valid mask {:x?}",
                pubdata.flags, HIBERNATE_META_VALID_FLAGS
            )));
        }

        Ok(Self {
            image_size: pubdata.image_size,
            flags: pubdata.flags,
            pagemap_pages: pubdata.pagemap_pages,
            header_hash: [0u8; HIBERNATE_HASH_SIZE],
            data_key: [0u8; HIBERNATE_DATA_KEY_SIZE],
            data_iv: [0u8; HIBERNATE_DATA_IV_SIZE],
            first_data_byte: pubdata.first_data_byte,
            meta_iv: pubdata.private_iv,
            meta_key: None,
            meta_eph_public: pubdata.meta_eph_public,
            private_blob: Some(pubdata.private),
            save_private_data: true,
        })
    }

    /// Load the metadata from disk, and populates the structure based on the
    /// public data. The private data is left in a blob.
    pub fn load_from_disk(disk_file: &mut BouncedDiskFile) -> Result<Self> {
        let mut buf = vec![0u8; 4096];
        let mut slice = [IoSliceMut::new(&mut buf)];
        let bytes_read = match disk_file.read_vectored(&mut slice) {
            Ok(s) => s,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read < std::mem::size_of::<PublicHibernateMetadata>() {
            return Err(HibernateError::MetadataError(
                "Read too few bytes".to_string(),
            ));
        }

        // This is safe because the buffer is larger than the structure size, and the types
        // in the struct are all basic.
        let public_data: PublicHibernateMetadata = unsafe {
            std::ptr::read_unaligned(
                buf[0..std::mem::size_of::<PublicHibernateMetadata>()].as_ptr() as *const _,
            )
        };

        Self::load_from_data(&public_data)
    }

    /// Set the key used to encrypt/decrypt the private metadata.
    pub fn set_metadata_key(&mut self, key: [u8; HIBERNATE_DATA_KEY_SIZE]) {
        self.meta_key = Some(key);
    }

    /// Decrypt the private metadata contents via a key set previously by
    /// set_metadata_key(), and populate it into the current object.
    pub fn load_private_data(&mut self) -> Result<()> {
        if matches!(self.meta_key, None) {
            return Err(HibernateError::MetadataError(
                "Cannot load private data without meta key".to_string(),
            ));
        }

        // Decrypt the private data.
        let cipher = Cipher::aes_128_cbc();
        let mut crypter = Crypter::new(
            cipher,
            Mode::Decrypt,
            &self.meta_key.unwrap(),
            Some(&self.meta_iv),
        )
        .unwrap();
        crypter.pad(true);
        let mut private_buf = vec![0u8; HIBERNATE_META_PRIVATE_SIZE + cipher.block_size()];
        let decrypt_size = match crypter.update(&self.private_blob.unwrap(), &mut private_buf) {
            Ok(s) => s,
            Err(e) => {
                return Err(HibernateError::MetadataError(format!(
                    "Decryption error: {}",
                    e
                )))
            }
        };

        if decrypt_size < std::mem::size_of::<PrivateHibernateMetadata>() {
            return Err(HibernateError::MetadataError(format!(
                "Private metadata was {:x?} bytes, expected at least {:x?}",
                decrypt_size,
                std::mem::size_of::<PrivateHibernateMetadata>()
            )));
        }

        // This is safe because we just validated we decrypted the structure
        // size (above), and the types in the struct are all basic.
        let private_data: PrivateHibernateMetadata = unsafe {
            std::ptr::read_unaligned(
                private_buf[0..std::mem::size_of::<PrivateHibernateMetadata>()].as_ptr()
                    as *const _,
            )
        };

        self.apply_private_data(&private_data)
    }

    /// Apply private metadata info from a given C struct into the current
    /// object.
    fn apply_private_data(&mut self, privdata: &PrivateHibernateMetadata) -> Result<()> {
        if privdata.version != HIBERNATE_META_VERSION {
            return Err(HibernateError::MetadataError(format!(
                "Invalid private metadata version: {:x?}, expected {:x?}",
                privdata.version, HIBERNATE_META_VERSION
            )));
        }

        if self.image_size != privdata.image_size {
            return Err(HibernateError::MetadataError(format!(
                "Mismatch in public private image size: {:x?} vs {:x?}",
                privdata.image_size, self.image_size
            )));
        }

        if self.pagemap_pages != privdata.pagemap_pages {
            return Err(HibernateError::MetadataError(format!(
                "Mismatch in pagemap count: {:x?} vs {:x?}",
                privdata.pagemap_pages, self.pagemap_pages
            )));
        }

        self.header_hash = privdata.header_hash;
        self.data_key = privdata.data_key;
        self.data_iv = privdata.data_iv;
        self.flags = privdata.flags;
        Ok(())
    }

    /// Save the current metadata contents to disk. If dont_save_private_data()
    /// has been called, then only the public portions are saved, and the
    /// private portion is zeroed out. This is useful on resume when the caller
    /// wants to update flags and clear the private area.
    pub fn write_to_disk(&self, disk_file: &mut BouncedDiskFile) -> Result<()> {
        let mut buf = vec![0u8; 4096];

        // Check the flags being written in case somebody added a flag and
        // forgot to add it to the valid mask.
        if (self.flags & !HIBERNATE_META_VALID_FLAGS) != 0 {
            return Err(HibernateError::MetadataError(format!(
                "Invalid flags: {:x?}, valid mask {:x?}",
                self.flags, HIBERNATE_META_VALID_FLAGS
            )));
        }

        assert!(buf.len() >= std::mem::size_of::<PublicHibernateMetadata>());

        let public_data = self.build_public_data(self.save_private_data)?;
        unsafe {
            // Copy the struct into the beginning of the u8 buffer. This is safe
            // because the buffer was allocated to be larger than this struct
            // size.
            buf[0..std::mem::size_of::<PublicHibernateMetadata>()]
                .copy_from_slice(any_as_u8_slice(&public_data));
        }

        let bytes_written = match disk_file.write(&buf[..]) {
            Ok(s) => s,
            Err(e) => {
                return Err(HibernateError::FileIoError(
                    "Failed to write metadata".to_string(),
                    e,
                ))
            }
        };

        if bytes_written != buf.len() {
            return Err(HibernateError::MetadataError(
                "Wrote too few bytes".to_string(),
            ));
        }

        Ok(())
    }

    /// Stop including the private metadata when saving to disk. This is useful
    /// upon resume when we want to update the flags, but there will be no more
    /// resume attempts with this image (because the attempt is in progress), so
    /// the private metadata can be cleared.
    pub fn dont_save_private_data(&mut self) {
        self.save_private_data = false;
    }

    /// Create the public C struct from the current object contents.
    fn build_public_data(&self, include_private: bool) -> Result<PublicHibernateMetadata> {
        let private = match include_private {
            true => self.build_private_buffer()?,
            false => [0u8; HIBERNATE_META_PRIVATE_SIZE],
        };

        let private_iv = match include_private {
            true => self.meta_iv,
            false => [0u8; HIBERNATE_DATA_IV_SIZE],
        };

        let meta_eph_public = match include_private {
            true => self.meta_eph_public,
            false => [0u8; HIBERNATE_META_KEY_SIZE],
        };

        Ok(PublicHibernateMetadata {
            magic: HIBERNATE_META_MAGIC,
            version: HIBERNATE_META_VERSION,
            pagemap_pages: self.pagemap_pages,
            image_size: self.image_size,
            flags: self.flags,
            first_data_byte: self.first_data_byte,
            meta_eph_public,
            private_iv,
            private,
        })
    }

    /// Construct the encrypted private buffer area.
    fn build_private_buffer(&self) -> Result<[u8; HIBERNATE_META_PRIVATE_SIZE]> {
        let mut buf = [0u8; HIBERNATE_META_PRIVATE_SIZE];
        let private_data = self.build_private_data();

        if matches!(self.meta_key, None) {
            return Err(HibernateError::MetadataError(
                "Cannot build private metadata without meta key".to_string(),
            ));
        }

        // Encrypt it into the buffer.
        let cipher = Cipher::aes_128_cbc();
        let mut crypter = Crypter::new(
            cipher,
            Mode::Encrypt,
            &self.meta_key.unwrap(),
            Some(&self.meta_iv),
        )
        .unwrap();
        crypter.pad(true);
        // It's safe to call as_any_u8_slice() with the private data because the
        // encrypter can handle the raw bytes.
        let encrypt_size;
        unsafe {
            encrypt_size = match crypter.update(any_as_u8_slice(&private_data), &mut buf) {
                Ok(s) => s,
                Err(e) => {
                    return Err(HibernateError::MetadataError(format!(
                        "Encryption error: {}",
                        e
                    )))
                }
            };
        }

        if let Err(e) = crypter.finalize(&mut buf[encrypt_size..]) {
            return Err(HibernateError::MetadataError(format!(
                "Encryption error: {}",
                e
            )));
        }

        Ok(buf)
    }

    /// Construct the private metadata C structure contents.
    fn build_private_data(&self) -> PrivateHibernateMetadata {
        PrivateHibernateMetadata {
            version: HIBERNATE_META_VERSION,
            pagemap_pages: self.pagemap_pages,
            image_size: self.image_size,
            flags: self.flags,
            data_key: self.data_key,
            data_iv: self.data_iv,
            header_hash: self.header_hash,
        }
    }

    /// Fill a buffer with random bytes, given an open file to /dev/urandom.
    fn fill_random(buf: &mut [u8]) -> Result<()> {
        if let Err(e) = rand_bytes(buf, Source::Pseudorandom) {
            return Err(HibernateError::RandomError(e));
        }

        Ok(())
    }
}
