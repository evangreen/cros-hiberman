// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Coordinates suspend-to-disk activities

use hiberman;
use sys_util::{error, syslog};

fn print_usage(message: &str, error: bool) {
    if error {
        eprintln!("{}", message)
    } else {
        println!("{}", message);
    }
}

fn hibernate_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman hibernate [options]
Hibernate the system now.

Options are:
    --dry-run -- Create the hibernate image, but then exit rather than
        shutting down. Note that it's not safe to resume to this image
        as the file systems will likely be modified after the process
        exits. Use this only for testing the hibernate sequence, in
        tandem with resume --dry-run.
    --help -- Print this help text.
"#;

    print_usage(usage_msg, error);
}

fn hiberman_hibernate(args: &mut std::env::Args) -> std::result::Result<(), ()> {
    let mut dry_run = false;
    for arg in args {
        match arg.as_ref() {
            "--help" | "-h" => {
                hibernate_usage(false);
                return Ok(());
            }

            "--dry-run" | "-n" => {
                dry_run = true;
            }

            _ => {
                error!("invalid argument: {}", arg);
                return Err(());
            }
        }
    }

    if let Err(e) = hiberman::hibernate(dry_run) {
        error!("Failed to hibernate: {}", e);
        return Err(());
    }

    Ok(())
}

fn resume_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman resume [options]
Resume the system now. On success, does not return, but jumps back into the
resumed image.

Options are:
    -n, --dry-run -- Load the resume image, but don't actually jump into it.
    --help -- Print this help text.
"#;

    print_usage(usage_msg, error);
}

fn hiberman_resume(args: &mut std::env::Args) -> std::result::Result<(), ()> {
    let mut dry_run = false;
    for arg in args {
        match arg.as_ref() {
            "--help" | "-h" => {
                resume_usage(false);
                return Ok(());
            }

            "-n" | "--dry-run" => {
                dry_run = true;
            }

            _ => {
                error!("invalid argument: {}", arg);
                return Err(());
            }
        }
    }

    if let Err(e) = hiberman::resume(dry_run) {
        error!("Failed to resume: {}", e);
        return Err(());
    }

    Ok(())
}

fn app_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman subcommand [options]
This application coordinates suspend-to-disk activities. Try
hiberman <subcommand> --help for details on specific subcommands.

Valid subcommands are:
    help -- Print this help text.
    hibernate -- Suspend the machine to disk now.
    resume -- Resume the system now.
"#;
    print_usage(usage_msg, error);
}

fn hiberman_main() -> std::result::Result<(), ()> {
    let mut args = std::env::args();
    if let Err(e) = syslog::init() {
        println!("failed to initialize syslog: {}", e);
        return Err(());
    }

    if args.next().is_none() {
        error!("expected executable name.");
        return Err(());
    }

    let subcommand = match args.next() {
        Some(subcommand) => subcommand,
        None => {
            error!("expected a subcommand");
            return Err(());
        }
    };

    let mut args = std::env::args();
    args.next();
    args.next();
    match subcommand.as_ref() {
        "--help" | "-h" | "help" => {
            app_usage(false);
            return Ok(());
        }
        "hibernate" => hiberman_hibernate(&mut args),
        "resume" => hiberman_resume(&mut args),
        _ => {
            error!("unknown subcommand: {}", subcommand);
            return Err(());
        }
    }
}

fn main() {
    std::process::exit(if hiberman_main().is_ok() { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
}
