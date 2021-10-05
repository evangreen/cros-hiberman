// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement consistent logging across the hibernate and resume transition.
use crate::hiberutil::{HibernateError, Result};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::str;
use std::sync::{MutexGuard, Once};
use std::time::Instant;
use sync::Mutex;
pub use sys_util::syslog::{Facility, Priority};

// Define the mount location where the hibernate data is located.
pub static KMSG_PATH: &str = "/dev/kmsg";
// Define the prefix to go on log messages.
pub static LOG_PREFIX: &str = "hiberman";
// Define the default flush threshold. This must be a power of two.
pub static FLUSH_THRESHOLD: usize = 4096;

// Copied from sys_util/src/syslog.rs.
// TODO: Figure out how to modify sys_util so that we can just implement a backend here.
static STATE_ONCE: Once = Once::new();
static mut STATE: *const Mutex<Hiberlog> = 0 as *const _;

fn new_mutex_ptr<T>(inner: T) -> *const Mutex<T> {
    Box::into_raw(Box::new(Mutex::new(inner)))
}

/// Initialize the syslog connection and internal variables.
///
/// This should only be called once per process before any other threads have been spawned or any
/// signal handlers have been registered. Every call made after the first will have no effect
/// besides return `Ok` or `Err` appropriately.
pub fn init() -> Result<()> {
    let mut err = HibernateError::PoisonedError();
    STATE_ONCE.call_once(|| match Hiberlog::new() {
        // Safe because STATE mutation is guarded by `Once`.
        Ok(state) => unsafe { STATE = new_mutex_ptr(state) },
        Err(e) => err = e,
    });

    if unsafe { STATE.is_null() } {
        Err(err)
    } else {
        Ok(())
    }
}

fn lock() -> Result<MutexGuard<'static, Hiberlog>> {
    // Safe because we assume that STATE is always in either a valid or NULL state.
    let state_ptr = unsafe { STATE };
    if state_ptr.is_null() {
        return Err(HibernateError::LoggerUninitialized());
    }
    // Safe because STATE only mutates once and we checked for NULL.
    let state = unsafe { &*state_ptr };
    let guard = state.lock();
    Ok(guard)
}

// Attempts to lock and retrieve the state. Returns from the function silently on failure.
macro_rules! lock {
    () => {
        match lock() {
            Ok(s) => s,
            _ => return,
        };
    };
}

/// A macro for logging at an arbitrary priority level.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! log {
    ($pri:expr, $($args:tt)+) => ({
        $crate::hiberlog::log($pri, $crate::hiberlog::Facility::User, Some((file!(), line!())), format_args!($($args)+))
    })
}

/// A macro for logging an error.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! error {
    ($($args:tt)+) => ($crate::log!($crate::hiberlog::Priority::Error, $($args)*))
}

/// A macro for logging a warning.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! warn {
    ($($args:tt)+) => ($crate::log!($crate::hiberlog::Priority::Warning, $($args)*))
}

/// A macro for logging info.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! info {
    ($($args:tt)+) => ($crate::log!($crate::hiberlog::Priority::Info, $($args)*))
}

/// A macro for logging debug information.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => ($crate::log!($crate::hiberlog::Priority::Debug, $($args)*))
}

pub enum HiberlogOut {
    BufferInMemory,
    Syslog,
    File,
}

struct Hiberlog {
    file: Option<Box<dyn Write>>,
    kmsg: File,
    start: Instant,
    partial: Option<Vec<u8>>,
    pending: Vec<Vec<u8>>,
    pending_size: usize,
    flush_threshold: usize,
    to_kmsg: bool,
    out: HiberlogOut,
    pid: u32,
}

impl Hiberlog {
    pub fn new() -> Result<Self> {
        let kmsg = match OpenOptions::new().read(true).write(true).open(KMSG_PATH) {
            Ok(f) => f,
            Err(e) => return Err(HibernateError::OpenFileError(KMSG_PATH.to_string(), e)),
        };

        Ok(Hiberlog {
            file: None,
            kmsg,
            start: Instant::now(),
            partial: None,
            pending: vec![],
            pending_size: 0,
            flush_threshold: FLUSH_THRESHOLD,
            to_kmsg: false,
            out: HiberlogOut::Syslog,
            pid: std::process::id(),
        })
    }

    pub fn log(
        &mut self,
        pri: Priority,
        fac: Facility,
        file_line: Option<(&str, u32)>,
        args: fmt::Arguments,
    ) {
        let mut buf = [0u8; 1024];

        // If sending to the syslog, just forward there and exit.
        if matches!(self.out, HiberlogOut::Syslog) {
            sys_util::syslog::log(pri, fac, file_line, args);
            return;
        }

        let res = {
            let mut buf_cursor = Cursor::new(&mut buf[..]);
            let facprio = (pri as usize) + (fac as usize);
            if let Some((file_name, line)) = &file_line {
                let duration = self.start.elapsed();
                write!(
                    &mut buf_cursor,
                    "<{}>{}: {}.{:03} {} [{}:{}:{}] ",
                    facprio,
                    LOG_PREFIX,
                    duration.as_secs(),
                    duration.subsec_millis(),
                    self.pid,
                    pri,
                    file_name,
                    line
                )
            } else {
                write!(&mut buf_cursor, "<{}>{}: ", facprio, LOG_PREFIX)
            }
            .and_then(|()| writeln!(&mut buf_cursor, "{}", args))
            .map(|()| buf_cursor.position() as usize)
        };

        if let Ok(len) = &res {
            if self.to_kmsg {
                let _ = self.kmsg.write_all(&buf[..*len]);
            }

            self.pending.push(buf[..*len].to_vec());
            self.pending_size += *len;
            self.flush_full_pages();
        }
    }

    fn flush_one_page(&mut self) {
        // Do nothing if buffering messages in memory.
        if matches!(self.out, HiberlogOut::BufferInMemory) {
            return;
        }

        // Start with the partial string from last time, or an empty buffer.
        let mut buf = Vec::<u8>::new();
        if let Some(v) = &self.partial {
            buf.extend(v);
        }

        self.partial = None;
        let mut partial = None;

        // Add as many whole lines into the buffer as will fit.
        let mut length = buf.len();
        let mut i = 0;
        while (i < self.pending.len()) && (length + self.pending[i].len() <= self.flush_threshold) {
            buf.extend(&self.pending[i]);
            length += self.pending[i].len();
            i += 1;
        }

        // Add a partial line or pad out the space if needed.
        if length < self.flush_threshold {
            let remainder = self.flush_threshold - length;
            if i < self.pending.len() {
                // Add a part of this line to the buffer to fill it out.
                buf.extend(&self.pending[i][..remainder]);
                length += remainder;

                // Save the rest of this line as the next partial, and advance over it.
                partial = Some(self.pending[i][remainder..].to_vec());
                i += 1;
            } else {
                // Fill the buffer with zeroes as a signal to stop reading.
                buf.extend(vec![0x0u8; remainder]);
            }
        }

        self.file.as_mut().and_then(|f| {
            let _ = f.write(&buf[..]);
            Some(f)
        });

        self.pending_size -= length;
        self.pending = self.pending[i..].to_vec();
        self.partial = partial;
    }

    fn flush_full_pages(&mut self) {
        // Do nothing if buffering messages in memory.
        if matches!(self.out, HiberlogOut::BufferInMemory) {
            return;
        }

        while self.pending_size >= self.flush_threshold {
            self.flush_one_page();
        }
    }

    pub fn flush(&mut self) {
        // Do a regular full-page flush, which be perfectly page aligned.
        self.flush_full_pages();
        // Flush one more page, which serves two purposes:
        // 1. Flushes out a partial page.
        // 2. Ensures that there's padding at the end, even if the data
        //    perfectly lines up with a page. This is used on read to know
        //    when to stop.
        self.flush_one_page();
    }

    // Push any pending lines to the syslog.
    pub fn flush_to_syslog(&mut self) {
        // Ignore the partial line, just replay pending lines.
        for line_vec in &self.pending {
            let mut len = line_vec.len();
            if len == 0 {
                continue;
            }

            len -= 1;
            let s = match str::from_utf8(&line_vec[0..len]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            replay_line(s.to_string());
        }

        self.reset();
    }
    pub fn reset(&mut self) {
        self.pending_size = 0;
        self.pending = vec![];
        self.partial = None;
    }
}

pub fn log(pri: Priority, fac: Facility, file_line: Option<(&str, u32)>, args: fmt::Arguments) {
    let mut state = lock!();
    state.log(pri, fac, file_line, args)
}

// Diverts the log to a new output. This does not flush or reset the stream, the caller must
// decide what they want to do with buffered output before calling this.
pub fn redirect_log(out: HiberlogOut, file: Option<Box<dyn Write>>) {
    let mut state = lock!();
    state.file = file;
    state.to_kmsg = false;
    // Any time we're redirecting to a file, also send to kmsg as a message
    // in a bottle, in case we never get a chance to replay our own file logs.
    // This shouldn't produce duplicate messages on success because when we're
    // logging to a file we're also barrelling towards a kexec or shutdown.
    if matches!(out, HiberlogOut::File) {
        state.to_kmsg = true;
    }

    state.out = out;
    // If going back to syslog, dump any pending state into syslog.
    if matches!(state.out, HiberlogOut::Syslog) {
        state.flush_to_syslog();
    }
}

// Discard any buffered but unsent logging data.
pub fn reset_log() {
    let mut state = lock!();
    state.reset();
}

// Flush any pending messages out to the file, and add a terminator.
pub fn flush_log() {
    let mut state = lock!();
    state.flush();
}

// Replay a log file to syslog.
pub fn replay_log_file(file: &mut dyn Read, name: &str) {
    // Read the file until the first null byte is found, which
    // signifies the end of the log.
    let mut reader = BufReader::new(file);
    let mut buf = Vec::<u8>::new();
    if let Err(e) = reader.read_until(0, &mut buf) {
        warn!("Failed to replay log file: {}", e);
        return;
    }

    sys_util::syslog::log(
        Priority::Info,
        Facility::User,
        None,
        format_args!("Replaying {}:", name),
    );
    // Now split that big buffer into lines and feed it into the log.
    let len_without_delim = buf.len() - 1;
    let cursor = Cursor::new(&buf[..len_without_delim]);
    let reader = BufReader::new(cursor);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        replay_line(line);
    }

    sys_util::syslog::log(
        Priority::Info,
        Facility::User,
        None,
        format_args!("Done replaying {}", name),
    );
}

fn replay_line(line: String) {
    // The log lines are in kmsg format, like:
    // <11>hiberman: [src/hiberman.rs:529] Hello 2004
    // Trim off the first colon, evertything after is line contents.
    let mut elements = line.splitn(2, ": ");
    let header = elements.next().unwrap();
    let contents = match elements.next() {
        Some(c) => c,
        None => {
            warn!(
                "Failed to split on colon: header: {}, line {:x?}, len {}",
                header,
                line.as_bytes(),
                line.len()
            );
            return;
        }
    };

    // Now trim <11>hiberman into <11, and parse 11 out of the combined
    // priority + facility.
    let facprio_string = header.splitn(2, ">").next().unwrap();
    let facprio: u8 = match facprio_string[1..].parse() {
        Ok(i) => i,
        Err(_) => {
            warn!("Failed to parse facprio for next line, using debug");
            debug!("{}", contents);
            return;
        }
    };

    // Parse out the facility and priority, and feed it back into the logger.
    let facility = facprio & (0x17 << 3);
    // This is safe because facility has defined all possible values for the
    // mask we just applied.
    let facility: Facility = unsafe { ::std::mem::transmute(facility) };
    // This is safe because all possible 8 values are defined in Priority.
    let priority: Priority = unsafe { ::std::mem::transmute(facprio & 7) };
    sys_util::syslog::log(priority, facility, None, format_args!("{}", contents));
}