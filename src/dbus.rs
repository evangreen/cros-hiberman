// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles the D-Bus interface for hibernate.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use dbus::blocking::Connection;
use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus_crossroads::{Context, Crossroads};
use log::{debug, error, info};
use protobuf::{Message, SingularPtrField};
use sync::Mutex;
use system_api::client::OrgChromiumUserDataAuthInterface;
use system_api::rpc::AccountIdentifier;
use system_api::UserDataAuth::{GetHibernateSecretReply, GetHibernateSecretRequest};

use crate::hiberutil::HibernateError;

/// Define the minimum acceptable seed material length.
const MINIMUM_SEED_SIZE: usize = 32;

// Define the timeout to connect to the dbus system.
pub const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(25);

/// Define the context shared between dbus calls. These must all have the Send
/// trait.
struct HibernateDbusStateInternal {
    call_count: u32,
    seed_material: Vec<u8>,
    account_id: String,
    barrier: Arc<Barrier>,
}

impl HibernateDbusStateInternal {
    fn new() -> Self {
        Self {
            call_count: 0,
            seed_material: vec![],
            account_id: String::new(),
            barrier: Arc::new(Barrier::new(2)),
        }
    }

    /// D-bus method called by cryptohome to set secret seed material derived
    /// from user authentication.
    fn set_seed_material(&mut self, seed: &[u8]) {
        info!("Received {} bytes of seed material", seed.len());
        self.call_count += 1;
        self.seed_material = seed.to_owned();
    }

    /// D-bus method called by login_manager to let the hibernate service
    /// know a user session is about to be started.
    fn resume_from_hibernate(&mut self, account_id: &str) {
        self.call_count += 1;
        self.account_id = account_id.to_string();
        // This first wait on the barrier releases the main thread now that the
        // ResumeFromHibernate call has in fact been called.
        self.barrier.wait();
    }
}

/// Define the d-bus state. Arc and Mutex are needed because crossroads takes
/// ownership of the state passed in, and requires the Send trait.
#[derive(Clone)]
struct HibernateDbusState(Arc<Mutex<HibernateDbusStateInternal>>);

impl HibernateDbusState {
    fn new() -> Self {
        HibernateDbusState(Arc::new(Mutex::new(HibernateDbusStateInternal::new())))
    }
}

/// Define the connection details to Dbus. This is the unprotected version, to
/// be manipulated after acquiring the lock.
struct HiberDbusConnectionInternal {
    conn: Connection,
    state: HibernateDbusState,
}

impl HiberDbusConnectionInternal {
    /// Fire up a new system d-bus server.
    fn new(state: HibernateDbusState) -> Result<Self> {
        info!("Setting up dbus");
        let conn = Connection::new_system().context("Failed to start local dbus connection")?;
        conn.request_name("org.chromium.Hibernate", false, false, false)
            .context("Failed to request dbus name")?;

        let mut crossroads = Crossroads::new();
        // Build a new HibernateSeedInterface.
        let iface_token = crossroads.register("org.chromium.HibernateSeedInterface", |b| {
            // Let's add a method to the interface. We have the method name,
            // followed by names of input and output arguments (used for
            // introspection). The closure then controls the types of these
            // arguments. The last argument to the closure is a tuple of the
            // input arguments.
            b.method(
                "SetSeedMaterial",
                ("seed",),
                (),
                move |_ctx: &mut Context, state: &mut HibernateDbusState, (seed,): (Vec<u8>,)| {
                    // Here's what happens when the method is called.
                    state.0.lock().set_seed_material(&seed);
                    Ok(())
                },
            );
        });

        crossroads.insert("/org/chromium/Hibernate", &[iface_token], state.clone());
        // Build a new HibernateResumeInterface.
        let iface_token = crossroads.register("org.chromium.HibernateResumeInterface", |b| {
            b.method(
                "ResumeFromHibernate",
                ("account_id",),
                (),
                move |_ctx: &mut Context,
                      state: &mut HibernateDbusState,
                      (account_id,): (String,)| {
                    // Here's what happens when the method is called.
                    let barrier;
                    // Call the handler function with the lock held. Also grab
                    // a copy of the barrier to wait with the lock not held.
                    let mut internal_state = state.0.lock();
                    internal_state.resume_from_hibernate(&account_id);
                    barrier = internal_state.barrier.clone();
                    drop(internal_state);
                    info!("ResumeFromHibernate: waiting on main thread");
                    // Perform the second of two waits on the barrier from the
                    // dbus thread. The main thread will release this thread
                    // when it's ok to return from this method and let boot
                    // proceed. This is done without the state locked so the
                    // main thread can access the state.
                    barrier.wait();
                    info!("ResumeFromHibernate completing");
                    Ok(())
                },
            );
        });
        crossroads.insert("/org/chromium/Hibernate", &[iface_token], state.clone());
        conn.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                if let Err(e) = crossroads.handle_message(msg, conn) {
                    error!("Failed to handle message: {:?}", e);
                    false
                } else {
                    true
                }
            }),
        );

        info!("Completed dbus setup");
        Ok(HiberDbusConnectionInternal { conn, state })
    }

    /// Public function used by the dbus thread to process requests until the
    /// resume method gets called. At that point we drop off since that's all we
    /// need.
    fn receive_seed(&mut self) -> Result<()> {
        info!("Looping to receive ResumeFromHibernate dbus call");
        loop {
            self.conn
                .process(Duration::from_millis(30000))
                .context("Failed to process")?;
            // Break out if the account ID became populated.
            let state = self.state.0.lock();
            if !state.account_id.is_empty() {
                break;
            }

            debug!("Still waiting for ResumeFromHibernate dbus call");
        }

        Ok(())
    }
}

/// Define the thread safe version of the dbus connection state.
pub struct HiberDbusConnection {
    internal: Arc<Mutex<HiberDbusConnectionInternal>>,
    thread: Option<thread::JoinHandle<()>>,
    state: HibernateDbusState,
}

impl HiberDbusConnection {
    /// Create a new dbus connection and announce ourselves on the bus. This
    /// function does not start serving requests yet though.
    pub fn new() -> Result<Self> {
        let state = HibernateDbusState::new();
        Ok(HiberDbusConnection {
            internal: Arc::new(Mutex::new(HiberDbusConnectionInternal::new(state.clone())?)),
            thread: None,
            state,
        })
    }

    /// Fire up a thread to respond to dbus requests.
    pub fn spawn_dbus_server(&mut self) -> Result<()> {
        let arc_clone = Arc::clone(&self.internal);
        self.thread = Some(thread::spawn(move || {
            debug!("Started dbus server thread");
            let mut conn = arc_clone.lock();
            let _ = conn.receive_seed();
            debug!("Exiting dbus server thread");
        }));

        Ok(())
    }

    /// Block waiting for the seed material to become available from cryptohome,
    /// then return that material.
    pub fn get_seed_material(&mut self, resume_in_progress: bool) -> Result<PendingResumeCall> {
        let barrier = self.state.0.lock().barrier.clone();

        // This is the first (of two) barrier waits from the main thread, which
        // blocks until the dbus thread receives a ResumeFromHibernate call.
        info!("Waiting for ResumeFromHibernate call");
        barrier.wait();

        // If there's no resume in progress, do the second barrier wait right
        // away to unblock the method and the rest of boot.
        if !resume_in_progress {
            info!("Unblocking ResumeFromHibernate immediately");
            barrier.wait();
        }

        // Now grab the state to get the account ID out.
        info!("Acquiring dbus state");
        let state = self.state.0.lock();
        info!("Requesting secret seed");
        let secret_seed = get_secret_seed(state.account_id.to_string())?;
        let length = secret_seed.len();
        if length < MINIMUM_SEED_SIZE {
            return Err(HibernateError::DbusError(format!(
                "Seed size {} was below minium {}",
                length, MINIMUM_SEED_SIZE
            )))
            .context("Failed to receive seed");
        }

        info!("Got {} bytes of seed material", length);
        drop(state);
        Ok(PendingResumeCall {
            secret_seed,
            dbus_connection: if resume_in_progress { Some(self) } else { None },
        })
    }
}

/// This struct serves as a ticket indicating that the dbus thread is currently
/// blocked in the ResumeFromHibernate method.
pub struct PendingResumeCall<'a> {
    pub secret_seed: Vec<u8>,
    dbus_connection: Option<&'a mut HiberDbusConnection>,
}

impl Drop for PendingResumeCall<'_> {
    fn drop(&mut self) {
        // This is the second barrier wait from the main thread, which releases
        // the d-bus thread waiting in the ResumeFromHibernate method call.
        if self.dbus_connection.is_some() {
            info!("Unblocking pending resume call");
            self.dbus_connection
                .as_ref()
                .unwrap()
                .state
                .0
                .lock()
                .barrier
                .wait();
        }
    }
}

/// Ask cryptohome for the hibernate seed for the given account. This call only
/// works once, then cryptohome forgets the secret.
fn get_secret_seed(account_id: String) -> Result<Vec<u8>> {
    let conn = Connection::new_system().context("Failed to connect to dbus for secret seed")?;
    let conn_path = conn.with_proxy(
        "org.chromium.UserDataAuth",
        "/org/chromium/UserDataAuth",
        DEFAULT_DBUS_TIMEOUT,
    );

    let mut proto: GetHibernateSecretRequest = Message::new();
    let mut account_identifier = AccountIdentifier::new();
    account_identifier.set_account_id(account_id);
    proto.account_id = SingularPtrField::some(account_identifier);
    let response = conn_path
        .get_hibernate_secret(proto.write_to_bytes().unwrap())
        .context("Failed to call GetHibernateSecret dbus method")?;
    let response: GetHibernateSecretReply = Message::parse_from_bytes(&response)
        .context("Failed to parse GetHibernateSecret dbus response")?;
    Ok(response.hibernate_secret)
}
