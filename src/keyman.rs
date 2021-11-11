// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement key management of the top level asymmetric key pair, used to
//! protect the hibernate metadata encryption key.

use std::convert::TryInto;
use std::fs::create_dir;
use std::fs::File;
use std::io::{IoSlice, Read, Write};
use std::path::Path;

use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private, Public};

use crate::hibermeta::{HibernateMetadata, HIBERNATE_DATA_KEY_SIZE, HIBERNATE_META_KEY_SIZE};
use crate::hiberutil::{HibernateError, Result};
use crate::{error, info, warn};

/// Define the ramfs location where the hibernate public key is stored.
static PUBLIC_KEY_DIR: &str = "/run/hibernate/";
/// Define the name where the hibernate public key is stored.
static PUBLIC_KEY_NAME: &str = "pubkey";
/// Define the fixed test key seed, used when a developer wants to hibernate or
/// resume now with --test-keys.
const TEST_KEY_MATERIAL: &[u8; HIBERNATE_META_KEY_SIZE] = b"TestHibernateKeyMaterial12345678";

/// The HibernateKeyManager stores the public and private key pair. The public
/// side is used to encrypt the hibernate metadata at suspend time. The private
/// side is used to decrypt that same private metadata. An asymmetric key is
/// used so that the hibernate image decryption key is not sitting around in
/// memory during most of boot.
pub struct HibernateKeyManager {
    private_key: Option<PKey<Private>>,
    public_key: Option<PKey<Public>>,
}

impl HibernateKeyManager {
    /// Create a new HibernateKeyManager, with no keys.
    pub fn new() -> Self {
        HibernateKeyManager {
            private_key: None,
            public_key: None,
        }
    }

    /// Use the test keys.
    pub fn use_test_keys(&mut self) -> Result<()> {
        warn!("Using test keys: File a bug if you see this in production");
        // Don't clobber already loaded keys.
        assert!(matches!(self.private_key, None) && matches!(self.public_key, None));

        self.set_private_key(&TEST_KEY_MATERIAL[..])?;
        let public_bytes = self.private_key.as_ref().unwrap().raw_public_key().unwrap();
        self.public_key = Some(PKey::public_key_from_raw_bytes(&public_bytes, Id::X25519).unwrap());
        Ok(())
    }

    /// Create the private (and public) key based on secret seed material.
    pub fn set_private_key(&mut self, key: &[u8]) -> Result<()> {
        let private_key = PKey::private_key_from_raw_bytes(key, Id::X25519).unwrap();
        self.private_key = Some(private_key);
        Ok(())
    }

    /// Save the public key to a ramfs file so it can be used later by the
    /// hibernate service.
    pub fn save_public_key(&self) -> Result<()> {
        if matches!(self.private_key, None) {
            return Err(HibernateError::KeyManagerError(
                "No public key to save".to_string(),
            ));
        }

        if let Err(e) = create_dir(PUBLIC_KEY_DIR) {
            return Err(HibernateError::CreateDirectoryError(
                PUBLIC_KEY_DIR.to_string(),
                e,
            ));
        }

        let key_path = Path::new(PUBLIC_KEY_DIR).join(PUBLIC_KEY_NAME);
        info!("Saving public key to {}", key_path.display());
        let mut key_file = File::create(&key_path)
            .map_err(|e| HibernateError::OpenFileError(key_path.display().to_string(), e))?;
        let public_key = &self.private_key.as_ref().unwrap().raw_public_key().unwrap();

        assert!(public_key.len() == HIBERNATE_META_KEY_SIZE);

        let slice = [IoSlice::new(public_key)];
        let bytes_written = match key_file.write_vectored(&slice) {
            Ok(b) => b,
            Err(e) => {
                return Err(HibernateError::FileIoError(
                    "Failed to write".to_string(),
                    e,
                ))
            }
        };

        if bytes_written != public_key.len() {
            return Err(HibernateError::KeyManagerError(
                "Wrote too few bytes".to_string(),
            ));
        }

        Ok(())
    }

    /// Load the public key from a ramfs file, that was previously saved by a
    /// different instance of this application calling save_public_key().
    pub fn load_public_key(&mut self) -> Result<()> {
        let key_path = Path::new(PUBLIC_KEY_DIR).join(PUBLIC_KEY_NAME);
        info!("Loading public key from {}", key_path.display());
        let mut key_file = match File::open(&key_path) {
            Ok(f) => f,
            Err(e) => {
                // Cryptohome should have handed the hibernate key to another
                // instance of this program. If you see this message, that
                // instance probably didn't launch, or never received keys from
                // cryptohome.
                error!("No hibernate public key. Use --test-keys to hibernate now");
                return Err(HibernateError::OpenFileError(
                    key_path.display().to_string(),
                    e,
                ));
            }
        };

        let mut public_key = [0u8; HIBERNATE_META_KEY_SIZE];
        let bytes_read = match key_file.read(&mut public_key) {
            Ok(b) => b,
            Err(e) => return Err(HibernateError::FileIoError("Failed to read".to_string(), e)),
        };

        if bytes_read != public_key.len() {
            return Err(HibernateError::KeyManagerError(
                "Read too few bytes".to_string(),
            ));
        }

        self.public_key = Some(PKey::public_key_from_raw_bytes(&public_key, Id::X25519).unwrap());
        Ok(())
    }

    /// Generate a new metadata key by generating a random ephemeral asymmetric
    /// key and doing Diffie-Hellman to get a symmetric key. The caller must
    /// have previously called load_public_key() or use_test_key(). On success,
    /// the symmetric key will be installed in the given metadata instance.
    pub fn install_new_metadata_key(&mut self, metadata: &mut HibernateMetadata) -> Result<()> {
        // Use the public key. The private key will also do.
        let public_key = match &self.public_key {
            Some(k) => k,
            None => {
                return Err(HibernateError::KeyManagerError(
                    "Unpopulated public key".to_string(),
                ))
            }
        };

        // Create a new random key, and fire up a DH shared secret.
        let ephemeral_key = PKey::generate_x25519().unwrap();
        let mut deriver = Deriver::new(&ephemeral_key).unwrap();
        deriver.set_peer(public_key).unwrap();

        // Install the ephemeral public key into the metadata.
        let ephemeral_public = ephemeral_key.raw_public_key().unwrap();
        metadata.meta_eph_public = ephemeral_public.try_into().unwrap();

        // Derive and install the derived key into the metadata.
        self.install_derived_key(metadata, &mut deriver)
    }

    /// Generate the metadata key by doing Diffie-Hellman with the previously
    /// saved ephemeral public key, and the auth public/private key. The caller
    /// must have previously called set_private_key().
    pub fn install_saved_metadata_key(&mut self, metadata: &mut HibernateMetadata) -> Result<()> {
        if matches!(self.private_key, None) {
            return Err(HibernateError::KeyManagerError(
                "Unpopulated private key".to_string(),
            ));
        }

        // Load the ephemeral public key.
        let ephemeral_public =
            PKey::public_key_from_raw_bytes(&metadata.meta_eph_public, Id::X25519).unwrap();
        // Fire up a DH and load both keys.
        let mut deriver = Deriver::new(self.private_key.as_ref().unwrap()).unwrap();
        deriver.set_peer(&ephemeral_public).unwrap();

        // Derive and install the derived key into the metadata.
        self.install_derived_key(metadata, &mut deriver)
    }

    /// Derive the shared key, and install it into the metadata for future
    /// encryption or decryption of private data.
    fn install_derived_key(
        &self,
        metadata: &mut HibernateMetadata,
        deriver: &mut Deriver,
    ) -> Result<()> {
        assert!(deriver.len().unwrap() >= HIBERNATE_META_KEY_SIZE);

        let mut derived_metadata_key = vec![0u8; deriver.len().unwrap()];
        let key_size = match deriver.derive(&mut derived_metadata_key) {
            Ok(s) => s,
            Err(e) => {
                return Err(HibernateError::KeyManagerError(format!(
                    "Failed to derive: {}",
                    e
                )))
            }
        };

        if key_size != derived_metadata_key.len() {
            return Err(HibernateError::KeyManagerError(format!(
                "Derived size {}, expected {}",
                key_size,
                derived_metadata_key.len()
            )));
        }

        // Install the shared key into the metadata.
        metadata.set_metadata_key(
            derived_metadata_key[..HIBERNATE_DATA_KEY_SIZE]
                .try_into()
                .unwrap(),
        );
        Ok(())
    }
}
