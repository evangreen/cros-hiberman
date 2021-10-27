// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Listing for hibernate library components.

pub mod cat;
pub mod cookie;
mod crypto;
mod dbus;
mod diskfile;
mod fiemap;
mod files;
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
mod sysfs;

use hiberutil::Result;
pub use hiberutil::{HibernateOptions, ResumeOptions};
use resume::ResumeConductor;
use suspend::SuspendConductor;

pub fn hibernate(options: HibernateOptions) -> Result<()> {
    let mut conductor = SuspendConductor::new()?;
    conductor.hibernate(options)
}

pub fn resume(options: ResumeOptions) -> Result<()> {
    let mut conductor = ResumeConductor::new()?;
    conductor.resume(options)
}
